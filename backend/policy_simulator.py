"""
policy_simulator.py — SecurePass AI

Simulates the impact of enforcing stronger password policies on dataset health.

FIX SUMMARY:
- Added _simulate_sequential_blocking() for the new sequential_numbers pattern.
- projected_score is now guaranteed to be >= current_score (improvement is
  always non-negative — was already true mathematically but now explicit).
- _calculate_improvement_percentage() returns 0 when current == projected
  rather than dividing by zero if current == 0.
- _generate_summary() thresholds re-calibrated to be more meaningful for
  scores in the 0–30 gain range typical of most datasets.
- Added 'improvement_details' key listing the per-policy score gains for
  display in the frontend / PDF.
"""

from typing import Any, Dict, List


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def simulate_policy_impact(
    current_score: float,
    pattern_stats: Dict[str, Any],
    dataset_stats: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Simulate the improvement achievable by enforcing stronger policies.

    Args:
        current_score:  Current password health score (0–100)
        pattern_stats:  Output of pattern_detector.detect_patterns()
        dataset_stats:  Output of dataset_analyzer.analyze_dataset()

    Returns dict with:
        current_score, projected_score, improvement_percentage,
        policies_simulated, improvement_details, summary
    """
    if not (0 <= current_score <= 100):
        return _default_simulation_result(current_score)

    if not pattern_stats or not dataset_stats:
        return _default_simulation_result(current_score)

    gains: Dict[str, float] = {
        'minimum_length_12':       _simulate_length_policy(dataset_stats),
        'dictionary_blocking':     _simulate_dictionary_blocking(pattern_stats),
        'keyboard_pattern_blocking': _simulate_pattern_blocking(pattern_stats),
        'sequential_blocking':     _simulate_sequential_blocking(pattern_stats),
        'duplicate_prevention':    _simulate_duplicate_prevention(dataset_stats),
    }

    total_gain    = sum(gains.values())
    projected     = min(100.0, current_score + total_gain)
    projected     = max(projected, current_score)   # never go below current
    improvement_pct = _improvement_percentage(current_score, projected)
    summary       = _generate_summary(current_score, projected)

    return {
        'current_score':         round(current_score, 2),
        'projected_score':       round(projected, 2),
        'improvement_percentage': round(improvement_pct, 2),
        'policies_simulated':    _policy_labels(),
        'improvement_details':   {k: round(v, 2) for k, v in gains.items()},
        'summary':               summary,
    }


# ────────────────────────────────────────────────────────────────────────────
#  Per-policy gain estimators
# ────────────────────────────────────────────────────────────────────────────

def _simulate_length_policy(dataset_stats: Dict[str, Any]) -> float:
    """Enforce 12+ character minimum."""
    ld    = dataset_stats.get('length_distribution', {})
    total = dataset_stats.get('total_passwords', 0)
    if total == 0:
        return 0.0

    short_ratio  = ld.get('less_than_8', 0) / total
    medium_ratio = ld.get('8_to_11', 0)     / total
    return (short_ratio * 20.0) + (medium_ratio * 8.0)


def _simulate_dictionary_blocking(pattern_stats: Dict[str, Any]) -> float:
    """Block dictionary words, names, and simple numeric suffixes."""
    patterns = pattern_stats.get('patterns', {})
    if not patterns:
        return 0.0

    dict_pct   = patterns.get('dictionary_based', {}).get('percentage', 0.0)
    name_pct   = patterns.get('name_based',        {}).get('percentage', 0.0)
    suffix_pct = patterns.get('numeric_suffix',    {}).get('percentage', 0.0)

    return (dict_pct / 100.0) * 6.0 + (name_pct / 100.0) * 5.0 + (suffix_pct / 100.0) * 4.0


def _simulate_pattern_blocking(pattern_stats: Dict[str, Any]) -> float:
    """Block keyboard walks, capitalisation misuse, and leet speak."""
    patterns = pattern_stats.get('patterns', {})
    if not patterns:
        return 0.0

    kbd_pct  = patterns.get('keyboard_walk',         {}).get('percentage', 0.0)
    cap_pct  = patterns.get('capitalization_misuse', {}).get('percentage', 0.0)
    leet_pct = patterns.get('leetspeak',             {}).get('percentage', 0.0)

    return (kbd_pct / 100.0) * 5.0 + (cap_pct / 100.0) * 3.0 + (leet_pct / 100.0) * 4.0


def _simulate_sequential_blocking(pattern_stats: Dict[str, Any]) -> float:
    """Block sequential numeric passwords (123456, 111111, etc.)."""
    patterns = pattern_stats.get('patterns', {})
    if not patterns:
        return 0.0
    seq_pct = patterns.get('sequential_numbers', {}).get('percentage', 0.0)
    return (seq_pct / 100.0) * 5.0


def _simulate_duplicate_prevention(dataset_stats: Dict[str, Any]) -> float:
    """Prevent password reuse."""
    total = dataset_stats.get('total_passwords', 0)
    dups  = dataset_stats.get('duplicate_passwords', 0)
    if total == 0:
        return 0.0
    return (dups / total) * 7.0


# ────────────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────────────

def _improvement_percentage(current: float, projected: float) -> float:
    if current == 0 or projected <= current:
        return 0.0
    return ((projected - current) / current) * 100.0


def _policy_labels() -> List[str]:
    return [
        'Minimum length (12+ characters)',
        'Dictionary word blocking',
        'Name-based password blocking',
        'Keyboard pattern blocking',
        'Sequential number blocking',
        'Duplicate password prevention',
        'Simple pattern restrictions',
    ]


def _generate_summary(current: float, projected: float) -> str:
    gain = projected - current
    if gain < 2:
        return 'Minimal improvement expected. The current password set is relatively strong.'
    if gain < 10:
        return f'Moderate improvement of {gain:.1f} points achievable through targeted policy enforcement.'
    if gain < 25:
        return f'Significant improvement of {gain:.1f} points possible with stronger password policies.'
    return (
        f'Substantial improvement of {gain:.1f} points is achievable. '
        'Immediate policy updates are strongly recommended.'
    )


def _default_simulation_result(current_score: float) -> Dict[str, Any]:
    return {
        'current_score':          round(current_score, 2),
        'projected_score':        round(current_score, 2),
        'improvement_percentage': 0.0,
        'policies_simulated':     _policy_labels(),
        'improvement_details':    {},
        'summary':                'Unable to simulate policy impact due to insufficient data.',
    }