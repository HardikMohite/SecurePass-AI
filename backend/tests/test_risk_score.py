"""
Unit test for backend/risk_score.py — calculate_risk_score() against
fixed, hand-computed dataset_stats / pattern_stats inputs (no breach
data), verifying the exact penalty math and resulting distribution.

Inputs (total_passwords = 100):
    length_distribution: less_than_8=50, 8_to_11=50, 12_to_15=0, 16_plus=0
    duplicate_passwords: 10
    invalid_or_empty_count: 5
    patterns: dictionary_based count=50/percentage=50.0, all others 0

Expected penalties:
    length_penalty    = min(0.5*30 + 0.5*10, 40) = min(15+5, 40)   = 20.0
    pattern_penalty   = (50/100) * weight[dictionary_based]=8.0    = 4.0
    duplicate_penalty = min(10/100 * 10, 10)                       = 1.0
    invalid_penalty   = min(5/100 * 10, 10)                        = 0.5
    breach_penalty                                                 = 0.0 (no breach_stats)
    total_penalty = 20 + 4 + 1 + 0.5 = 25.5
    score = 100 - 25.5 = 74.5  -> risk_level "Low" (score >= 70)

Expected distribution:
    pattern_high = int((50 + 0 + 0) * 0.7) = 35
    high   = min(less_8(50) + pattern_high(35), 100) = 85
    medium = min(8_to_11(50) + 0, 100 - 85) = 15
    low    = max(0, 100 - 85 - 15) = 0
"""
from risk_score import calculate_risk_score

_EMPTY_PATTERNS = {
    "dictionary_based": {"count": 0, "percentage": 0.0},
    "name_based": {"count": 0, "percentage": 0.0},
    "numeric_suffix": {"count": 0, "percentage": 0.0},
    "keyboard_walk": {"count": 0, "percentage": 0.0},
    "capitalization_misuse": {"count": 0, "percentage": 0.0},
    "leetspeak": {"count": 0, "percentage": 0.0},
    "sequential_numbers": {"count": 0, "percentage": 0.0},
}

DATASET_STATS = {
    "total_passwords": 100,
    "length_distribution": {
        "less_than_8": 50,
        "8_to_11": 50,
        "12_to_15": 0,
        "16_plus": 0,
    },
    "duplicate_passwords": 10,
    "invalid_or_empty_count": 5,
}

PATTERN_STATS = {
    "patterns": {
        **_EMPTY_PATTERNS,
        "dictionary_based": {"count": 50, "percentage": 50.0},
    }
}


def test_calculate_risk_score_value_and_level():
    result = calculate_risk_score(DATASET_STATS, PATTERN_STATS)
    assert result["score"] == 74.5
    assert result["risk_level"] == "Low"


def test_calculate_risk_score_penalty_breakdown():
    result = calculate_risk_score(DATASET_STATS, PATTERN_STATS)
    assert result["penalty_breakdown"] == {
        "length": 20.0,
        "patterns": 4.0,
        "duplicates": 1.0,
        "invalid": 0.5,
        "breach": 0.0,
    }


def test_calculate_risk_score_distribution():
    result = calculate_risk_score(DATASET_STATS, PATTERN_STATS)
    assert result["distribution"] == {"high": 85, "medium": 15, "low": 0}


def test_calculate_risk_score_no_breach_stats_omits_breach_key():
    result = calculate_risk_score(DATASET_STATS, PATTERN_STATS)
    assert "breach_statistics" not in result


def test_calculate_risk_score_empty_dataset_returns_default():
    result = calculate_risk_score({}, {})
    assert result["score"] == 0.0
    assert result["risk_level"] == "High"
