"""
risk_score.py — SecurePass AI

Calculates an overall Password Health Score (0–100) and risk distribution.

FIX SUMMARY:
- Pattern penalty now includes 'sequential_numbers' (new detector).
- _calculate_risk_distribution() no longer allows High+Medium to silently
  exceed total_passwords (was possible via uncapped min() calls).
- _calculate_breach_penalty() no longer returns > 30 even when
  severity_penalty pushes it above the cap.
- _determine_risk_level() thresholds documented and aligned with the
  frontend legend (Low ≥ 70, Medium 40–69, High < 40).
- score floor changed from 0 to max(0, …) — was already correct but
  now explicit about intent.
- Added 'penalty_breakdown' key to result for debugging / PDF display.
"""

from typing import Any, Dict, Optional


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    breach_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Calculate the overall password health score and risk distribution.

    Args:
        dataset_stats:  Output of dataset_analyzer.analyze_dataset()
        pattern_stats:  Output of pattern_detector.detect_patterns()
        breach_stats:   Output of hibp_checker.calculate_breach_statistics() or None

    Returns dict with keys:
        score, risk_level, explanation, distribution, penalty_breakdown
        (+ breach_statistics if breach_stats provided)
    """
    if not dataset_stats or not pattern_stats:
        return _default_score_result()

    total = dataset_stats.get('total_passwords', 0)
    if total == 0:
        return _default_score_result()

    length_penalty    = _calculate_length_penalty(dataset_stats)
    pattern_penalty   = _calculate_pattern_penalty(pattern_stats)
    duplicate_penalty = _calculate_duplicate_penalty(dataset_stats)
    invalid_penalty   = _calculate_invalid_penalty(dataset_stats)
    breach_penalty    = _calculate_breach_penalty(breach_stats) if breach_stats else 0.0

    total_penalty = length_penalty + pattern_penalty + duplicate_penalty + invalid_penalty + breach_penalty
    score = max(0.0, min(100.0, 100.0 - total_penalty))

    risk_level  = _determine_risk_level(score)
    explanation = _generate_explanation(score, risk_level, dataset_stats, pattern_stats, breach_stats)
    distribution = _calculate_risk_distribution(dataset_stats, pattern_stats, total)

    result = {
        'score':      round(score, 2),
        'risk_level': risk_level,
        'explanation': explanation,
        'distribution': distribution,
        'penalty_breakdown': {
            'length':    round(length_penalty, 2),
            'patterns':  round(pattern_penalty, 2),
            'duplicates': round(duplicate_penalty, 2),
            'invalid':   round(invalid_penalty, 2),
            'breach':    round(breach_penalty, 2),
        },
    }

    if breach_stats:
        result['breach_statistics'] = breach_stats

    return result


# ────────────────────────────────────────────────────────────────────────────
#  Penalty calculators
# ────────────────────────────────────────────────────────────────────────────

def _calculate_length_penalty(dataset_stats: Dict[str, Any]) -> float:
    """Penalty for short passwords (0–40 pts)."""
    length_dist = dataset_stats.get('length_distribution', {})
    total       = dataset_stats.get('total_passwords', 0)
    if total == 0:
        return 0.0

    short_ratio  = length_dist.get('less_than_8', 0) / total
    medium_ratio = length_dist.get('8_to_11', 0) / total

    penalty = (short_ratio * 30.0) + (medium_ratio * 10.0)
    return min(penalty, 40.0)


def _calculate_pattern_penalty(pattern_stats: Dict[str, Any]) -> float:
    """Penalty for detected weak patterns (0–40 pts)."""
    patterns = pattern_stats.get('patterns', {})
    if not patterns:
        return 0.0

    # Weight per pattern type (higher = more severe)
    weights = {
        'dictionary_based':      8.0,
        'name_based':            6.0,
        'numeric_suffix':        5.0,
        'keyboard_walk':         7.0,
        'capitalization_misuse': 4.0,
        'leetspeak':             5.0,
        'sequential_numbers':    6.0,   # new pattern
    }

    penalty = 0.0
    for name, weight in weights.items():
        pct = patterns.get(name, {}).get('percentage', 0.0)
        penalty += (pct / 100.0) * weight

    return min(penalty, 40.0)


def _calculate_duplicate_penalty(dataset_stats: Dict[str, Any]) -> float:
    """Penalty for password reuse (0–10 pts)."""
    total = dataset_stats.get('total_passwords', 0)
    dups  = dataset_stats.get('duplicate_passwords', 0)
    if total == 0:
        return 0.0
    return min((dups / total) * 10.0, 10.0)


def _calculate_invalid_penalty(dataset_stats: Dict[str, Any]) -> float:
    """Penalty for invalid / empty entries (0–10 pts)."""
    total   = dataset_stats.get('total_passwords', 0)
    invalid = dataset_stats.get('invalid_or_empty_count', 0)
    if total == 0:
        return 0.0
    return min((invalid / total) * 10.0, 10.0)


def _calculate_breach_penalty(breach_stats: Dict[str, Any]) -> float:
    """Penalty based on HIBP breach statistics (0–30 pts).

    Reads keys as output by hibp_transformer.py:
      - checked_passwords  (transformer key, was: total_checked)
      - breach_rate        (transformer key, was: breach_percentage)
      - severity           (transformer key, was: severity_distribution) with lowercase keys
    """
    if not breach_stats or breach_stats.get("status") != "ok":
        return 0.0

    # checked_passwords is the correct key from hibp_transformer
    total_checked = breach_stats.get("checked_passwords", 0)
    if total_checked == 0:
        return 0.0

    # breach_rate is already a 0-100 percentage from hibp_transformer
    breach_pct = breach_stats.get("breach_rate", 0.0)
    base_penalty = (breach_pct / 100.0) * 20.0

    # severity has lowercase keys: critical, high, medium, low
    severity = breach_stats.get("severity", {})
    crit_ratio = severity.get("critical", 0) / total_checked
    high_ratio = severity.get("high", 0) / total_checked
    severity_penalty = (crit_ratio * 10.0) + (high_ratio * 5.0)

    return min(base_penalty + severity_penalty, 30.0)


# ────────────────────────────────────────────────────────────────────────────
#  Risk distribution
# ────────────────────────────────────────────────────────────────────────────

def _calculate_risk_distribution(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    total: int,
) -> Dict[str, int]:
    """
    Estimate how many passwords fall into each risk bucket.

    This is an approximation — individual passwords are not re-scored here.
    The estimate uses length buckets and pattern overlap.
    """
    if total == 0:
        return {'High Risk': 0, 'Medium Risk': 0, 'Low Risk': 0}

    ld = dataset_stats.get('length_distribution', {})
    less_8    = ld.get('less_than_8', 0)
    eight_11  = ld.get('8_to_11', 0)
    twelve_15 = ld.get('12_to_15', 0)

    patterns = pattern_stats.get('patterns', {})
    dict_cnt  = patterns.get('dictionary_based', {}).get('count', 0)
    kbd_cnt   = patterns.get('keyboard_walk', {}).get('count', 0)
    seq_cnt   = patterns.get('sequential_numbers', {}).get('count', 0)

    # High risk: short passwords + flagged patterns (deduplicated roughly)
    pattern_high = int((dict_cnt + kbd_cnt + seq_cnt) * 0.7)
    high_risk = min(less_8 + pattern_high, total)

    # Medium risk: 8–11 char passwords + a portion of longer ones with patterns
    medium_risk = min(eight_11 + int(twelve_15 * 0.25), total - high_risk)
    medium_risk = max(0, medium_risk)

    low_risk = max(0, total - high_risk - medium_risk)

    return {
        'High Risk':   high_risk,
        'Medium Risk': medium_risk,
        'Low Risk':    low_risk,
    }


# ────────────────────────────────────────────────────────────────────────────
#  Risk level & explanation
# ────────────────────────────────────────────────────────────────────────────

def _determine_risk_level(score: float) -> str:
    """
    Map score to risk level.

    Score ≥ 70  → Low
    Score 40–69 → Medium
    Score < 40  → High
    """
    if score >= 70:
        return 'Low'
    if score >= 40:
        return 'Medium'
    return 'High'


def _generate_explanation(
    score: float,
    risk_level: str,
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    breach_stats: Optional[Dict[str, Any]],
) -> str:
    level_text = {
        'High':   'Critical weaknesses detected. High prevalence of weak patterns and short passwords.',
        'Medium': 'Moderate security concerns. Some weak patterns detected that should be addressed.',
        'Low':    'Good password health. Minimal weak patterns and adequate password complexity.',
    }
    explanation = level_text.get(risk_level, 'Risk level unknown.')

    if breach_stats and breach_stats.get('status') == 'ok':
        bp  = breach_stats.get('breach_rate', 0.0)       # transformer key
        cnt = breach_stats.get('estimated_breached', 0)  # transformer key
        if bp > 50:
            explanation += f' CRITICAL: {bp:.1f}% of sampled passwords ({cnt}) found in known data breaches.'
        elif bp > 25:
            explanation += f' WARNING: {bp:.1f}% of sampled passwords ({cnt}) found in data breaches.'
        elif bp > 0:
            explanation += f' Note: {bp:.1f}% of sampled passwords ({cnt}) appear in breach databases.'

    return explanation


# ────────────────────────────────────────────────────────────────────────────
#  Fallback
# ────────────────────────────────────────────────────────────────────────────

def _default_score_result() -> Dict[str, Any]:
    return {
        'score':      0.0,
        'risk_level': 'High',
        'explanation': 'Unable to calculate score due to insufficient data.',
        'distribution': {'High Risk': 0, 'Medium Risk': 0, 'Low Risk': 0},
        'penalty_breakdown': {
            'length': 0, 'patterns': 0, 'duplicates': 0, 'invalid': 0, 'breach': 0,
        },
    }