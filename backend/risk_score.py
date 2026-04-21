
from typing import Any, Dict, Optional


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    breach_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
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

    risk_level   = _determine_risk_level(score)
    explanation  = _generate_explanation(score, risk_level, dataset_stats, pattern_stats, breach_stats)
    distribution = _calculate_risk_distribution(dataset_stats, pattern_stats, total)

    result = {
        'score':      round(score, 2),
        'risk_level': risk_level,
        'explanation': explanation,
        'distribution': distribution,
        'penalty_breakdown': {
            'length':     round(length_penalty, 2),
            'patterns':   round(pattern_penalty, 2),
            'duplicates': round(duplicate_penalty, 2),
            'invalid':    round(invalid_penalty, 2),
            'breach':     round(breach_penalty, 2),
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
    medium_ratio = length_dist.get('8_to_11', 0)     / total
    return min((short_ratio * 30.0) + (medium_ratio * 10.0), 40.0)


def _calculate_pattern_penalty(pattern_stats: Dict[str, Any]) -> float:
    """Penalty for detected weak patterns (0–40 pts)."""
    patterns = pattern_stats.get('patterns', {})
    if not patterns:
        return 0.0
    weights = {
        'dictionary_based':      8.0,
        'name_based':            6.0,
        'numeric_suffix':        5.0,
        'keyboard_walk':         7.0,
        'capitalization_misuse': 4.0,
        'leetspeak':             5.0,
        'sequential_numbers':    6.0,
    }
    penalty = sum(
        (patterns.get(name, {}).get('percentage', 0.0) / 100.0) * weight
        for name, weight in weights.items()
    )
    return min(penalty, 40.0)


def _calculate_duplicate_penalty(dataset_stats: Dict[str, Any]) -> float:
    """Penalty for password reuse (0–10 pts)."""
    total = dataset_stats.get('total_passwords', 0)
    dups  = dataset_stats.get('duplicate_passwords', 0)
    if total == 0:
        return 0.0
    return min((dups / total) * 10.0, 10.0)


def _calculate_invalid_penalty(dataset_stats: Dict[str, Any]) -> float:
    """Penalty for invalid/empty entries (0–10 pts)."""
    total   = dataset_stats.get('total_passwords', 0)
    invalid = dataset_stats.get('invalid_or_empty_count', 0)
    if total == 0:
        return 0.0
    return min((invalid / total) * 10.0, 10.0)


def _calculate_breach_penalty(breach_stats: Dict[str, Any]) -> float:
    """
    Penalty based on HIBP breach statistics (0–30 pts).

    BUG-04 FIX:
      severity counts in breach_stats are already estimated for the FULL
      dataset by hibp_transformer.  They must be divided by total_passwords
      (full dataset size), not checked_passwords (sample size), to produce
      valid [0,1] ratios.  Using the sample size as denominator produced
      ratios well above 1 and allowed the severity sub-penalty to push the
      total past the 30-pt cap.
    """
    if not breach_stats or breach_stats.get("status") != "ok":
        return 0.0

    total_checked = breach_stats.get("checked_passwords", 0)
    if total_checked == 0:
        return 0.0

    breach_pct   = breach_stats.get("breach_rate", 0.0)   # already 0-100 %
    base_penalty = (breach_pct / 100.0) * 20.0

    # Use full-dataset size as denominator for severity ratios
    total_passwords = breach_stats.get("total_passwords", total_checked)
    if total_passwords == 0:
        return min(base_penalty, 30.0)

    severity     = breach_stats.get("severity", {})
    crit_ratio   = severity.get("critical", 0) / total_passwords   # FIX
    high_ratio   = severity.get("high",     0) / total_passwords   # FIX
    sev_penalty  = (crit_ratio * 10.0) + (high_ratio * 5.0)

    return min(base_penalty + sev_penalty, 30.0)


# ────────────────────────────────────────────────────────────────────────────
#  Risk distribution — canonical lowercase keys only
# ────────────────────────────────────────────────────────────────────────────

def _calculate_risk_distribution(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    total: int,
) -> Dict[str, int]:
    """
    Estimate how many passwords fall into each risk bucket.

    BUG-13 FIX: Returns only lowercase keys ('high', 'medium', 'low').
    The old dual-key dict with both 'High Risk' and 'high' caused fragile
    JS fallback chains in the frontend.  One schema, one key format.
    """
    if total == 0:
        return {'high': 0, 'medium': 0, 'low': 0}

    ld = dataset_stats.get('length_distribution', {})
    less_8    = ld.get('less_than_8', 0)
    eight_11  = ld.get('8_to_11', 0)
    twelve_15 = ld.get('12_to_15', 0)

    patterns  = pattern_stats.get('patterns', {})
    dict_cnt  = patterns.get('dictionary_based',   {}).get('count', 0)
    kbd_cnt   = patterns.get('keyboard_walk',       {}).get('count', 0)
    seq_cnt   = patterns.get('sequential_numbers',  {}).get('count', 0)

    pattern_high = int((dict_cnt + kbd_cnt + seq_cnt) * 0.7)
    high  = min(less_8 + pattern_high, total)
    medium = min(eight_11 + int(twelve_15 * 0.25), total - high)
    medium = max(0, medium)
    low   = max(0, total - high - medium)

    return {'high': high, 'medium': medium, 'low': low}


# ────────────────────────────────────────────────────────────────────────────
#  Risk level & explanation
# ────────────────────────────────────────────────────────────────────────────

def _determine_risk_level(score: float) -> str:
    if score >= 70: return 'Low'
    if score >= 40: return 'Medium'
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
        bp  = breach_stats.get('breach_rate', 0.0)
        cnt = breach_stats.get('estimated_breached', 0)
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
        'distribution': {'high': 0, 'medium': 0, 'low': 0},
        'penalty_breakdown': {
            'length': 0, 'patterns': 0, 'duplicates': 0, 'invalid': 0, 'breach': 0,
        },
    }