"""
dataset_analyzer.py — SecurePass AI

Dataset-level statistical analysis on a list of passwords.

FIX SUMMARY:
- length_distribution now includes '12_to_15' and '16_plus' buckets so
  risk_score.py can use finer-grained length data (previously only had
  '12_or_more' which merged these two groups).
- Added median_length and std_dev_length for richer reporting.
- Added character_composition stats (% with uppercase, lowercase, digits,
  special chars) — charts.py was estimating these with hardcoded values
  because they weren't computed here; now they come from real data.
- _filter_valid_passwords() strips Windows CR characters.
- All division protected against zero-total edge cases.
"""

import statistics
from typing import Any, Dict, List


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def analyze_dataset(passwords: List[str]) -> Dict[str, Any]:
    """
    Analyse a password dataset and return aggregate statistics.

    Returns:
        total_passwords         – int  (includes invalid entries)
        unique_passwords        – int
        duplicate_passwords     – int
        average_length          – float
        median_length           – float
        std_dev_length          – float
        min_length              – int
        max_length              – int
        length_distribution     – dict  (see _categorize_lengths)
        character_composition   – dict  (counts & percentages per char type)
        invalid_or_empty_count  – int
    """
    if not passwords:
        return _empty_dataset_result()

    valid = _filter_valid_passwords(passwords)
    invalid_count = len(passwords) - len(valid)

    if not valid:
        return _empty_dataset_result(total=len(passwords), invalid=invalid_count)

    lengths      = [len(p) for p in valid]
    unique_count = len(set(valid))

    return {
        'total_passwords':       len(passwords),
        'unique_passwords':      unique_count,
        'duplicate_passwords':   len(valid) - unique_count,
        'average_length':        _mean(lengths),
        'median_length':         statistics.median(lengths),
        'std_dev_length':        _std_dev(lengths),
        'min_length':            min(lengths),
        'max_length':            max(lengths),
        'length_distribution':   _categorize_lengths(lengths),
        'character_composition': _character_composition(valid),
        'invalid_or_empty_count': invalid_count,
    }


# ────────────────────────────────────────────────────────────────────────────
#  Private helpers
# ────────────────────────────────────────────────────────────────────────────

def _filter_valid_passwords(passwords: List[str]) -> List[str]:
    return [p.strip('\r\n ') for p in passwords if p and p.strip()]


def _mean(lengths: List[int]) -> float:
    if not lengths:
        return 0.0
    return round(sum(lengths) / len(lengths), 2)


def _std_dev(lengths: List[int]) -> float:
    if len(lengths) < 2:
        return 0.0
    return round(statistics.stdev(lengths), 2)


def _categorize_lengths(lengths: List[int]) -> Dict[str, int]:
    """
    Categorise passwords into length buckets.

    Buckets:
        less_than_8   – < 8 characters   (critically short)
        8_to_11       – 8–11 characters  (below recommended)
        12_to_15      – 12–15 characters (meets minimum best practice)
        16_plus       – 16+ characters   (strong / passphrase range)

    Note: risk_score.py uses 'less_than_8' and '8_to_11'.
          The finer split of 12+ into 12_to_15 / 16_plus enables
          more accurate distribution charts.
    """
    buckets: Dict[str, int] = {
        'less_than_8': 0,
        '8_to_11':     0,
        '12_to_15':    0,
        '16_plus':     0,
    }
    for length in lengths:
        if length < 8:
            buckets['less_than_8'] += 1
        elif length <= 11:
            buckets['8_to_11'] += 1
        elif length <= 15:
            buckets['12_to_15'] += 1
        else:
            buckets['16_plus'] += 1
    return buckets


def _character_composition(passwords: List[str]) -> Dict[str, Any]:
    """
    Count how many passwords contain each character class.

    Returns both raw counts and percentages so the charts module
    doesn't have to estimate with hardcoded values.
    """
    total = len(passwords)
    if total == 0:
        return {
            'uppercase': {'count': 0, 'percentage': 0.0},
            'lowercase': {'count': 0, 'percentage': 0.0},
            'digits':    {'count': 0, 'percentage': 0.0},
            'special':   {'count': 0, 'percentage': 0.0},
        }

    has_upper   = sum(1 for p in passwords if any(c.isupper() for c in p))
    has_lower   = sum(1 for p in passwords if any(c.islower() for c in p))
    has_digits  = sum(1 for p in passwords if any(c.isdigit() for c in p))
    has_special = sum(1 for p in passwords if any(not c.isalnum() for c in p))

    def _pct(n):
        return round(n / total * 100, 2)

    return {
        'uppercase': {'count': has_upper,   'percentage': _pct(has_upper)},
        'lowercase': {'count': has_lower,   'percentage': _pct(has_lower)},
        'digits':    {'count': has_digits,  'percentage': _pct(has_digits)},
        'special':   {'count': has_special, 'percentage': _pct(has_special)},
    }


def _empty_dataset_result(total: int = 0, invalid: int = 0) -> Dict[str, Any]:
    return {
        'total_passwords':       total,
        'unique_passwords':      0,
        'duplicate_passwords':   0,
        'average_length':        0.0,
        'median_length':         0.0,
        'std_dev_length':        0.0,
        'min_length':            0,
        'max_length':            0,
        'length_distribution': {
            'less_than_8': 0,
            '8_to_11':     0,
            '12_to_15':    0,
            '16_plus':     0,
        },
        'character_composition': {
            'uppercase': {'count': 0, 'percentage': 0.0},
            'lowercase': {'count': 0, 'percentage': 0.0},
            'digits':    {'count': 0, 'percentage': 0.0},
            'special':   {'count': 0, 'percentage': 0.0},
        },
        'invalid_or_empty_count': invalid,
    }