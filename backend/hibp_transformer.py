"""
hibp_transformer.py — SecurePass AI

This module transforms the raw output from the HIBP engine into a rich,
structured format suitable for direct consumption by the frontend UI.
"""
from typing import Dict

def transform_hibp_stats(hibp_data: Dict, total_passwords: int) -> Dict:
    """
    Transforms raw HIBP engine data into the final format for the API response.

    Args:
        hibp_data: The raw dictionary from `check_bulk_passwords`.
        total_passwords: The total number of passwords in the original dataset.

    Returns:
        A dictionary structured for the frontend.
    """
    if not hibp_data or hibp_data.get('status') != 'ok':
        return {
            "status": "error",
            "message": "HIBP analysis was skipped or failed.",
            "total_passwords": total_passwords,
            "checked_passwords": 0,
            "estimated_breached": 0,
            "clean_estimated": total_passwords,
            "breach_rate": 0.0,
            "exposure_level": "Not Available",
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }

    # --- Calculate Core Metrics ---
    estimated_breached = hibp_data.get('total_breached', 0)
    clean_estimated = max(0, total_passwords - estimated_breached)
    breach_rate = hibp_data.get('breach_percentage', 0.0) # Already a percentage

    # --- Determine Exposure Level ---
    if breach_rate > 50:
        exposure_level = "Critical"
    elif breach_rate > 20:
        exposure_level = "High"
    elif breach_rate > 5:
        exposure_level = "Medium"
    elif breach_rate > 0:
        exposure_level = "Low"
    else:
        exposure_level = "None"

    # --- Scale Severity Distribution ---
    # The engine gives severity for the *sample*, we need to estimate for the *full dataset*.
    sample_size = hibp_data.get('sample_size', 1)
    breached_in_sample = hibp_data.get('breached_in_sample', 0)
    
    # Avoid division by zero; if no breaches in sample, scaling is irrelevant.
    scaling_factor = (estimated_breached / breached_in_sample) if breached_in_sample > 0 else 0
    
    raw_severity = hibp_data.get('severity_distribution', {})
    scaled_severity = {
        "critical": round(raw_severity.get('Critical', 0) * scaling_factor),
        "high": round(raw_severity.get('High', 0) * scaling_factor),
        "medium": round(raw_severity.get('Medium', 0) * scaling_factor),
        "low": round(raw_severity.get('Low', 0) * scaling_factor),
    }

    # --- Assemble Final JSON Structure ---
    return {
        "status": "ok",
        "total_passwords": total_passwords,
        "checked_passwords": hibp_data.get('sample_size', 0),
        "breached_sample": breached_in_sample,
        "estimated_breached": estimated_breached,
        "clean_estimated": clean_estimated,
        "breach_rate": breach_rate,
        "exposure_level": exposure_level,
        "sampled": hibp_data.get('sampled', False),
        "severity": scaled_severity
    }
