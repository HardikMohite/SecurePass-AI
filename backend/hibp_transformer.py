"""
hibp_transformer.py — SecurePass AI  PATCHED
BUG-03 FIX: Removed double-scaling of severity distribution.
  - hibp_engine.py already scales severity from sample → full dataset.
  - Previous version re-applied a scaling_factor on the already-scaled
    values, producing numbers that could wildly exceed dataset size.
  - Fix: consume severity_distribution directly from the engine, only
    converting Title-case keys to lowercase for the frontend contract.
"""
from typing import Dict

def transform_hibp_stats(hibp_data: Dict, total_passwords: int) -> Dict:
    """
    Transform raw HIBP engine output into the final API response structure.

    Args:
        hibp_data:        Raw dict from check_bulk_passwords()
        total_passwords:  Total passwords in the original dataset

    Returns:
        Structured dict for the frontend (keys: status, severity, breach_rate, …)
    """
    if not hibp_data or hibp_data.get('status') != 'ok':
        return {
            "status":            "error",
            "message":           "HIBP analysis was skipped or failed.",
            "total_passwords":   total_passwords,
            "checked_passwords": 0,
            "estimated_breached": 0,
            "clean_estimated":   total_passwords,
            "breach_rate":       0.0,
            "exposure_level":    "Not Available",
            "severity":          {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

    # ── Core metrics ──────────────────────────────────────────────────────
    estimated_breached = hibp_data.get('total_breached', 0)
    clean_estimated    = max(0, total_passwords - estimated_breached)
    breach_rate        = hibp_data.get('breach_percentage', 0.0)  # already 0-100

    # ── Exposure level ────────────────────────────────────────────────────
    if breach_rate > 50:    exposure_level = "Critical"
    elif breach_rate > 20:  exposure_level = "High"
    elif breach_rate > 5:   exposure_level = "Medium"
    elif breach_rate > 0:   exposure_level = "Low"
    else:                   exposure_level = "None"

    # ── Severity distribution ─────────────────────────────────────────────
    # FIX: hibp_engine already scaled severity to the full dataset via:
    #   severity_distribution = {k: math.ceil(v * scaling) for k, v in raw_severity.items()}
    # We must NOT re-scale here.  Just convert Title-case → lowercase for the
    # frontend API contract.
    raw_severity = hibp_data.get('severity_distribution', {})
    severity = {
        "critical": raw_severity.get('Critical', 0),
        "high":     raw_severity.get('High',     0),
        "medium":   raw_severity.get('Medium',   0),
        "low":      raw_severity.get('Low',      0),
    }

    return {
        "status":             "ok",
        "total_passwords":    total_passwords,
        "checked_passwords":  hibp_data.get('sample_size', 0),
        "breached_sample":    hibp_data.get('breached_in_sample', 0),
        "estimated_breached": estimated_breached,
        "clean_estimated":    clean_estimated,
        "breach_rate":        breach_rate,
        "exposure_level":     exposure_level,
        "sampled":            hibp_data.get('sampled', False),
        "severity":           severity,
    }