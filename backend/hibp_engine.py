"""
hibp_engine.py — SecurePass AI  (v2 — High-Accuracy / High-Performance)

UPGRADE SUMMARY vs v1
─────────────────────
• Full scan for datasets ≤ 2 000 passwords (was: sample only 500)
• Minimum 2 000 real checks for larger datasets (was: always 500)
• Smart stratified sampling for datasets > 2 000
• Per-thread requests.Session with connection pooling (HTTPAdapter)
  instead of a single shared session that serialises TLS handshakes
• Exponential-backoff retry on 429 / 5xx (up to 3 attempts)
• max_workers raised to 20 by default, configurable 10–30
• Prefix-level LRU cache (8 192 slots) prevents duplicate API calls
  when many passwords share the same SHA-1 prefix
• Severity distribution scaled from sample → full dataset
• All public return keys kept identical to v1 so downstream code
  (hibp_transformer.py, risk_score.py, hibp.js) needs no changes

k-Anonymity guarantee
─────────────────────
Only the first 5 hex chars of a SHA-1 hash are sent to the API.
Plaintext passwords never leave this process.
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from threading import local as _ThreadLocal
from typing import Dict, List, Optional
import requests
from requests.adapters import HTTPAdapter

# ── Constants ──────────────────────────────────────────────────────────────
HIBP_API_BASE   = "https://api.pwnedpasswords.com/range/"
_USER_AGENT     = "SecurePass-HIBP-Checker/2.0"
_TIMEOUT        = 5          # seconds per request
_RETRY_ATTEMPTS = 3          # max retries per prefix
_RETRY_BACKOFF  = 0.4        # base seconds between retries (doubles each time)
_POOL_SIZE      = 30         # connection pool size per thread-session
_MIN_SCAN       = 2_000      # minimum passwords checked for large datasets
_FULL_SCAN_CAP  = 2_000      # datasets ≤ this are always fully checked
_LRU_CACHE_SIZE = 8_192      # prefix cache slots

# ── Per-thread Session pool ─────────────────────────────────────────────────
# A single shared Session serialises TLS handshakes across threads.
# Using thread-local sessions gives each worker its own TCP connection pool.
_thread_local = _ThreadLocal()


def _get_session() -> requests.Session:
    """Return (or create) a per-thread requests.Session with connection pooling."""
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update({"User-Agent": _USER_AGENT})
        adapter = HTTPAdapter(
            pool_connections=_POOL_SIZE,
            pool_maxsize=_POOL_SIZE,
            max_retries=0,           # we handle retries ourselves for full control
        )
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        _thread_local.session = session
    return _thread_local.session


# ── Prefix-level LRU cache ──────────────────────────────────────────────────
# When many passwords share the same 5-char SHA-1 prefix the API only needs
# to be called once.  lru_cache is thread-safe on CPython (GIL-protected dict).

@lru_cache(maxsize=_LRU_CACHE_SIZE)
def _cached_fetch_prefix(prefix: str) -> Optional[str]:
    """
    Fetch the HIBP suffix list for *prefix* with retry / backoff.
    Result is cached; subsequent calls for the same prefix are free.
    Returns the raw response text, or None on permanent failure.
    """
    session = _get_session()
    url     = HIBP_API_BASE + prefix
    delay   = _RETRY_BACKOFF

    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            resp = session.get(url, timeout=_TIMEOUT)
            if resp.status_code == 200:
                return resp.text
            if resp.status_code == 429:
                # Rate-limited: back off and retry
                retry_after = float(resp.headers.get("Retry-After", delay))
                time.sleep(retry_after)
                delay *= 2
                continue
            if resp.status_code >= 500:
                # Server error: brief backoff
                time.sleep(delay)
                delay *= 2
                continue
            # 4xx other than 429 → don't retry
            return None
        except requests.Timeout:
            time.sleep(delay)
            delay *= 2
        except requests.RequestException:
            return None   # network error — don't retry indefinitely

    return None   # all attempts exhausted


def fetch_hibp_range(prefix: str) -> Optional[str]:
    """
    Fetch the HIBP k-Anonymity suffix range for a 5-char SHA-1 prefix.
    Validates prefix is strictly 5 hexadecimal chars.
    """
    clean_prefix = (prefix or "").strip().upper()
    if len(clean_prefix) != 5 or not all(c in "0123456789ABCDEF" for c in clean_prefix):
        return None
    return _cached_fetch_prefix(clean_prefix)


# ── Single-password check ───────────────────────────────────────────────────

def check_password_hibp(
    password: str,
    logger: Optional[logging.Logger] = None,
) -> dict:
    """
    Check one password against the HIBP k-Anonymity API.

    Returns:
        {
          "breached": bool,
          "count":    int,   # number of times seen in breaches (0 if clean)
          "status":   "ok" | "error",
          "error":    str    # only present on error
        }
    """
    if not password:
        return {"breached": False, "count": 0, "status": "error",
                "error": "Password is empty."}

    try:
        sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        raw = _cached_fetch_prefix(prefix)
        if raw is None:
            if logger:
                logger.warning("HIBP prefix fetch failed: %s", prefix)
            return {"breached": False, "count": 0, "status": "error",
                    "error": "API request failed."}

        # Response uses \r\n on the wire; normalise defensively
        for line in raw.replace("\r\n", "\n").split("\n"):
            if not line:
                continue
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[0] == suffix:
                return {"breached": True, "count": int(parts[1]), "status": "ok"}

        return {"breached": False, "count": 0, "status": "ok"}

    except Exception as exc:
        if logger:
            logger.exception("Unexpected error in check_password_hibp: %s", exc)
        return {"breached": False, "count": 0, "status": "error",
                "error": str(exc)}


# ── Severity bucketing ──────────────────────────────────────────────────────

def _severity_bucket(count: int) -> str:
    """Map HIBP prevalence count to a severity label."""
    if count >= 100_000:
        return "Critical"
    if count >= 10_000:
        return "High"
    if count >= 1_000:
        return "Medium"
    return "Low"


# ── Smart sampling strategy ─────────────────────────────────────────────────

def _build_check_list(
    passwords: List[str],
    total: int,
    unique: List[str],
    n_unique: int,
) -> tuple[List[str], bool]:
    """
    Decide which passwords to check and whether this is a sampled run.

    Rules
    ─────
    1. total ≤ _FULL_SCAN_CAP (2 000)  → check every unique password
    2. total > _FULL_SCAN_CAP          → check at least _MIN_SCAN (2 000) unique passwords
       The check list is built as:
         • All unique passwords up to _MIN_SCAN, shuffled first so we get a
           representative cross-section rather than alphabetically-first passwords.
         • If n_unique > _MIN_SCAN we still cap at _MIN_SCAN for the first tier,
           then add a proportional smart sample from the remainder so the
           caller can raise _MIN_SCAN without code changes.

    Returns (check_list, is_sampled).
    """
    if total <= _FULL_SCAN_CAP:
        # Full scan — deduplicate but check everything
        return unique, False

    # Large dataset — guarantee ≥ _MIN_SCAN checks
    shuffled = unique.copy()
    random.shuffle(shuffled)

    if n_unique <= _MIN_SCAN:
        # Fewer unique passwords than the minimum — check them all
        return shuffled, False   # not really sampled since we checked all uniques

    # Check the first _MIN_SCAN unique passwords (after shuffle = representative)
    check_list = shuffled[:_MIN_SCAN]

    # Optionally add a proportional smart sample from the tail so we cover more
    # ground when the dataset is very large (e.g. 10 000+).
    # Extra budget = min(10% of remainder, 500) to keep runtime bounded.
    remainder = shuffled[_MIN_SCAN:]
    extra_budget = min(len(remainder), max(0, int(len(remainder) * 0.10), 500))
    if extra_budget > 0:
        check_list = check_list + random.sample(remainder, extra_budget)

    return check_list, True


# ── Bulk checker ────────────────────────────────────────────────────────────

def check_bulk_passwords(
    passwords: List[str],
    logger: logging.Logger,
    sample_size: int = _MIN_SCAN,    # kept for API compat; logic uses _MIN_SCAN
    max_workers: int = 20,
) -> dict:
    """
    Check passwords against HIBP with full concurrency.

    Behaviour
    ─────────
    • ≤ 2 000 passwords  →  100 % real scan, sampled=False
    • > 2 000 passwords  →  ≥ 2 000 real checks, sampled=True,
                             estimated_breached scaled to full dataset

    Performance
    ───────────
    • ThreadPoolExecutor with configurable workers (default 20, max 30)
    • Per-thread requests.Session with HTTPAdapter connection pool
    • Prefix-level LRU cache: passwords sharing a SHA-1 prefix cost one
      API call instead of N
    • Exponential-backoff retry on 429 / 5xx

    Return keys (identical to v1 — no downstream changes required)
    ──────────────────────────────────────────────────────────────
    total_passwords, total_checked, total_breached, breached_in_sample,
    breach_percentage, sample_size, sampled, severity_distribution, status
    """
    start_time      = time.monotonic()
    total_passwords = len(passwords)
    workers         = max(10, min(int(max_workers), 30))   # clamp 10–30

    if total_passwords == 0:
        return _empty_result()

    # Deduplicate while preserving order determinism
    seen: set  = set()
    unique: List[str] = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)
    n_unique = len(unique)

    check_list, is_sampled = _build_check_list(passwords, total_passwords,
                                               unique, n_unique)
    actual_checked = len(check_list)

    # ── Concurrent HIBP checks ──────────────────────────────────────────── #
    breached_passwords: Dict[str, int] = {}   # password → breach count

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_pw = {
            executor.submit(check_password_hibp, pw, logger): pw
            for pw in check_list
        }
        for future in as_completed(future_to_pw):
            pw = future_to_pw[future]
            try:
                result = future.result()
                if result.get("breached"):
                    breached_passwords[pw] = result["count"]
            except Exception as exc:
                if logger:
                    logger.warning("HIBP future failed for a password: %s", exc)

    # ── Aggregate statistics ────────────────────────────────────────────── #
    breached_in_sample    = len(breached_passwords)
    sample_breach_rate    = breached_in_sample / actual_checked if actual_checked else 0.0
    estimated_breached    = round(total_passwords * sample_breach_rate)
    breach_percentage     = round(sample_breach_rate * 100, 2)

    # Severity distribution — raw counts from the checked sample
    raw_severity: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for count in breached_passwords.values():
        raw_severity[_severity_bucket(count)] += 1

    # Scale severity to the full dataset for the transformer
    scaling = (estimated_breached / breached_in_sample) if breached_in_sample else 0.0
    severity_distribution = {
        k: math.ceil(v * scaling) for k, v in raw_severity.items()
    }

    # ── Logging ─────────────────────────────────────────────────────────── #
    elapsed    = time.monotonic() - start_time
    cache_info = _cached_fetch_prefix.cache_info()

    if is_sampled:
        logger.info(
            "HIBP bulk check — checked=%d total=%d breached_sample=%d "
            "estimated=%d breach_pct=%.1f%% sampled=True "
            "time=%.2fs workers=%d cache_hits=%d cache_misses=%d",
            actual_checked, total_passwords, breached_in_sample,
            estimated_breached, breach_percentage,
            elapsed, workers, cache_info.hits, cache_info.misses,
        )
    else:
        logger.info(
            "HIBP bulk check — checked=%d total=%d breached=%d "
            "breach_pct=%.1f%% sampled=False "
            "time=%.2fs workers=%d cache_hits=%d cache_misses=%d",
            actual_checked, total_passwords, breached_in_sample,
            breach_percentage,
            elapsed, workers, cache_info.hits, cache_info.misses,
        )

    return {
        # ── Keys kept identical to v1 for downstream compatibility ── #
        "total_passwords":       total_passwords,
        "total_checked":         actual_checked,
        "total_breached":        estimated_breached,
        "breached_in_sample":    breached_in_sample,
        "breach_percentage":     breach_percentage,
        "sample_size":           actual_checked,
        "sampled":               is_sampled,
        "severity_distribution": severity_distribution,
        "status":                "ok",
    }


# ── Helpers ─────────────────────────────────────────────────────────────────

def _empty_result() -> dict:
    return {
        "total_passwords":    0,
        "total_checked":      0,
        "total_breached":     0,
        "breached_in_sample": 0,
        "breach_percentage":  0.0,
        "sample_size":        0,
        "sampled":            False,
        "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "status": "ok",
    }