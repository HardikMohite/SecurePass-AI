"""
attack_simulator.py — Password Cracking Simulation Lab
=======================================================
Educational simulation only. Estimates what percentage of passwords
in a dataset would be vulnerable to common attack strategies.

Attack types simulated:
  1. Dictionary Attack       — password appears in a known wordlist
  2. Keyboard Walk Attack    — sequential keyboard patterns (qwerty, 123456, etc.)
  3. Common Pattern Attack   — 6 pattern groups: word+digits, digits+word,
                               word+special, word+digits+special,
                               repeated blocks, leet-speak variants
  4. Brute Force Estimate    — passwords short enough to brute-force quickly

No actual cracking is performed. All logic is pure pattern matching.
"""

import re
import logging
from typing import Iterable

logger = logging.getLogger(__name__)

# ── Built-in keyboard walk seeds (expanded at runtime) ───────────────────────
_KEYBOARD_WALKS: tuple[str, ...] = (
    'qwerty', 'qwertyuiop',
    'asdf',   'asdfghjkl',
    'zxcv',   'zxcvbnm',
    '1234',   '12345', '123456', '1234567', '12345678', '123456789',
    '0987',   '09876', '098765',
    'abcd',   'abcdef',
    'aaaa',   'aaaaaa',
    '1111',   '111111',
    'pass',
)

# ── Common pattern regexes (each targets a distinct structural weakness) ─────
#
#  Group 1 — Word + digits suffix          password123 / admin2024 / hello99
_PAT_WORD_DIGITS    = re.compile(r'^[a-zA-Z]{3,}\d{1,6}$')
#  Group 2 — Digits prefix + word          123password / 2024admin / 99hello
_PAT_DIGITS_WORD    = re.compile(r'^\d{1,6}[a-zA-Z]{3,}$')
#  Group 3 — Word + special-char suffix    password! / admin@ / hello#
_PAT_WORD_SPECIAL   = re.compile(r'^[a-zA-Z]{3,}[^a-zA-Z0-9]{1,3}$')
#  Group 4 — Word + digits + special       Summer2026! / Pass99# / Hello1@
_PAT_WORD_DIG_SPC   = re.compile(r'^[a-zA-Z]{3,}\d{1,4}[^a-zA-Z0-9]{1,3}$')
#  Group 5a — Consecutive doubled-char groups   aabbcc / 112233 / aaabbb
_PAT_REPEAT_PAIRS   = re.compile(r'^((.)\2+){2,}$')
#  Group 5b — Repeated substring block          abcabc / 123123 / qwqwqw
_PAT_REPEAT_SUB     = re.compile(r'^(.{2,4})\1+$')
#  Group 6 — Leet-speak pure-word  p4ssword / passw0rd / @dmin / $ecret
#            detected via normalisation: result is pure alpha word ≥ 3 chars
_PAT_PURE_ALPHA     = re.compile(r'^[a-zA-Z]{3,}$')

# Leet-speak substitution map — normalise before pattern matching
_LEET_MAP: dict[str, str] = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '7': 't', '@': 'a', '$': 's',
    '!': 'i', '+': 't', '8': 'b',
}

# Structural regexes for direct matching (Groups 1-5)
_PATTERN_CHECKS: tuple = (
    _PAT_WORD_DIGITS,
    _PAT_DIGITS_WORD,
    _PAT_WORD_SPECIAL,
    _PAT_WORD_DIG_SPC,
    _PAT_REPEAT_PAIRS,
    _PAT_REPEAT_SUB,
)

# Structural regexes applied to leet-normalised string (Groups 1-4 + pure-alpha)
_LEET_CHECKS: tuple = (
    _PAT_WORD_DIGITS,
    _PAT_DIGITS_WORD,
    _PAT_WORD_SPECIAL,
    _PAT_WORD_DIG_SPC,
    _PAT_PURE_ALPHA,       # catches p4ssw0rd → "password" (pure alpha after normalise)
)

# ── Brute-force threshold ─────────────────────────────────────────────────────
_BRUTE_FORCE_MAX_LEN = 6   # passwords ≤ this length are flagged


class AttackSimulator:
    """
    Simulate common password attack strategies against a password dataset.

    Parameters
    ----------
    passwords : list[str]
        The list of plaintext passwords to analyse.
    wordlist : set[str] | list[str] | None
        Optional external wordlist for the dictionary attack.
        If None, a small built-in list is used as a fallback.

    Usage
    -----
    >>> sim = AttackSimulator(passwords, wordlist)
    >>> results = sim.run_all()
    """

    # Built-in fallback wordlist (top ~50 most common passwords)
    _BUILTIN_WORDLIST: frozenset[str] = frozenset({
        'password', '123456', '123456789', '12345678', '12345',
        'qwerty', 'abc123', 'monkey', 'letmein', 'dragon',
        'master', 'login', 'welcome', 'admin', 'pass',
        'shadow', 'superman', 'michael', 'football', 'baseball',
        'iloveyou', 'trustno1', 'sunshine', 'princess', 'starwars',
        'whatever', 'hello', 'charlie', 'donald', 'password1',
        '1q2w3e', 'qazwsx', 'zaq1zaq1', '1qaz2wsx',
        'password123', 'admin123', 'welcome1', 'root', 'toor',
        'test', 'guest', 'user', 'changeme', 'secret',
        'abc', '111111', '000000', 'passw0rd', 'p@ssword',
    })

    # ── Maximum dataset size to analyse in one run ────────────────────────────
    _MAX_PASSWORDS = 50_000

    def __init__(
        self,
        passwords: list[str],
        wordlist: Iterable[str] | None = None,
    ) -> None:
        if not isinstance(passwords, list):
            raise TypeError('passwords must be a list of strings.')

        # Sanitise and cap the dataset
        self._passwords: list[str] = [
            str(p).strip() for p in passwords
            if p and isinstance(p, str) and len(str(p).strip()) > 0
        ][:self._MAX_PASSWORDS]

        self._total: int = len(self._passwords)

        # Build wordlist (external takes priority; fall back to built-in)
        if wordlist is not None:
            try:
                self._wordlist: frozenset[str] = frozenset(
                    str(w).strip().lower() for w in wordlist if w
                )
            except Exception as exc:
                logger.warning('Failed to load external wordlist: %s — using built-in.', exc)
                self._wordlist = self._BUILTIN_WORDLIST
        else:
            self._wordlist = self._BUILTIN_WORDLIST

        # Pre-build lowercase walk set for fast O(1) lookups
        self._walk_set: frozenset[str] = frozenset(
            w.lower() for w in _KEYBOARD_WALKS
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def run_all(self) -> dict:
        """
        Run all four attack simulations and return a results dict.

        Returns
        -------
        dict with keys:
            dictionary_attack     : float  — % vulnerable
            keyboard_walk_attack  : float  — % vulnerable
            pattern_attack        : float  — % vulnerable
            brute_force_estimate  : float  — % vulnerable
            total_analysed        : int    — passwords processed
            simulated             : bool   — always True (flags educational use)
        """
        if self._total == 0:
            logger.warning('AttackSimulator: empty password list — returning zeros.')
            return self._zero_result()

        try:
            results = {
                'dictionary_attack':    self._pct(self._dictionary_attack()),
                'keyboard_walk_attack': self._pct(self._keyboard_walk_attack()),
                'pattern_attack':       self._pct(self._common_pattern_attack()),
                'brute_force_estimate': self._pct(self._brute_force_estimate()),
                'total_analysed':       self._total,
                'simulated':            True,
            }
            logger.info(
                'AttackSimulator: analysed %d passwords — dict=%.1f%% walk=%.1f%% '
                'pattern=%.1f%% brute=%.1f%%',
                self._total,
                results['dictionary_attack'],
                results['keyboard_walk_attack'],
                results['pattern_attack'],
                results['brute_force_estimate'],
            )
            return results

        except Exception as exc:
            logger.exception('AttackSimulator.run_all failed: %s', exc)
            return self._zero_result()

    # ── Private simulation methods ────────────────────────────────────────────

    def _dictionary_attack(self) -> int:
        """
        Count passwords that appear verbatim (case-insensitive) in the wordlist.
        """
        count = 0
        for pw in self._passwords:
            if pw.lower() in self._wordlist:
                count += 1
        return count

    def _keyboard_walk_attack(self) -> int:
        """
        Count passwords that contain a known keyboard walk sequence
        (e.g. qwerty, 123456, asdf).
        """
        count = 0
        for pw in self._passwords:
            lower = pw.lower()
            for walk in self._walk_set:
                if walk in lower:
                    count += 1
                    break   # count each password once
        return count

    def _common_pattern_attack(self) -> int:
        """
        Count passwords matching any of six structural weakness patterns:
          1. Word + digit suffix    — password123, admin2024
          2. Digit prefix + word    — 123password, 2024admin
          3. Word + special suffix  — password!, admin@
          4. Word + digit + special — Summer2026!, Pass99#
          5. Repeated char blocks   — aabbcc, 112233, aaabbb
          6. Leet-speak variants    — p4ssword, passw0rd, @dmin, $ecret
        Each password is counted at most once regardless of how many groups match.
        """
        count = 0
        for pw in self._passwords:
            # ── Groups 1-5: direct structural regex checks ────────────────
            if any(rx.match(pw) for rx in _PATTERN_CHECKS):
                count += 1
                continue

            # ── Group 6: leet-speak normalisation then re-check ──────────
            normalised = pw
            for leet_char, plain_char in _LEET_MAP.items():
                normalised = normalised.replace(leet_char, plain_char)

            if normalised != pw:                          # only if any substitution happened
                if any(rx.match(normalised) for rx in _LEET_CHECKS):
                    count += 1

        return count

    def _brute_force_estimate(self) -> int:
        """
        Count passwords short enough (≤ threshold) to brute-force quickly.
        """
        count = 0
        for pw in self._passwords:
            if len(pw) <= _BRUTE_FORCE_MAX_LEN:
                count += 1
        return count

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _pct(self, count: int) -> float:
        """Convert a raw count to a rounded percentage of the total dataset."""
        if self._total == 0:
            return 0.0
        return round(count / self._total * 100, 1)

    def _zero_result(self) -> dict:
        return {
            'dictionary_attack':    0.0,
            'keyboard_walk_attack': 0.0,
            'pattern_attack':       0.0,
            'brute_force_estimate': 0.0,
            'total_analysed':       0,
            'simulated':            True,
        }
