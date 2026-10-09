"""
Unit test for backend/dataset_analyzer.py — analyze_dataset() against a
small, fixed input list with hand-verified expected output.

Fixture: ["abc", "password1", "Str0ng!Pass12", "hi", "hi"]
  lengths: 3, 9, 13, 2, 2  (5 entries, "hi" duplicated once)
    -> total_passwords=5, unique_passwords=4, duplicate_passwords=1
    -> average_length = (3+9+13+2+2)/5 = 29/5 = 5.8
    -> median_length  = median([2,2,3,9,13]) = 3
    -> min_length=2, max_length=13
  length buckets (</8, 8-11, 12-15, 16+):
    "abc"(3), "hi"(2), "hi"(2)      -> less_than_8 = 3
    "password1"(9)                  -> 8_to_11     = 1
    "Str0ng!Pass12"(13)             -> 12_to_15    = 1
    (none)                          -> 16_plus      = 0
  character composition (out of 5 passwords):
    uppercase: only "Str0ng!Pass12" has an uppercase char -> count=1 (20%)
    lowercase: all 5 have a lowercase char                -> count=5 (100%)
    digits:    "password1" and "Str0ng!Pass12"            -> count=2 (40%)
    special:   only "Str0ng!Pass12" has '!'                -> count=1 (20%)
"""
from dataset_analyzer import analyze_dataset

PASSWORDS = ["abc", "password1", "Str0ng!Pass12", "hi", "hi"]


def test_analyze_dataset_totals_and_length_stats():
    result = analyze_dataset(PASSWORDS)
    assert result["total_passwords"] == 5
    assert result["unique_passwords"] == 4
    assert result["duplicate_passwords"] == 1
    assert result["average_length"] == 5.8
    assert result["median_length"] == 3
    assert result["min_length"] == 2
    assert result["max_length"] == 13
    assert result["invalid_or_empty_count"] == 0


def test_analyze_dataset_length_distribution_buckets():
    result = analyze_dataset(PASSWORDS)
    assert result["length_distribution"] == {
        "less_than_8": 3,
        "8_to_11": 1,
        "12_to_15": 1,
        "16_plus": 0,
    }


def test_analyze_dataset_character_composition():
    result = analyze_dataset(PASSWORDS)
    comp = result["character_composition"]
    assert comp["uppercase"]["count"] == 1
    assert comp["lowercase"]["count"] == 5
    assert comp["digits"]["count"] == 2
    assert comp["special"]["count"] == 1
    assert comp["lowercase"]["percentage"] == 100.0


def test_analyze_dataset_empty_input_returns_zeroed_result():
    result = analyze_dataset([])
    assert result["total_passwords"] == 0
    assert result["unique_passwords"] == 0
    assert result["length_distribution"] == {
        "less_than_8": 0,
        "8_to_11": 0,
        "12_to_15": 0,
        "16_plus": 0,
    }


def test_analyze_dataset_counts_blank_lines_as_invalid():
    result = analyze_dataset(["abc", "", "   ", "defgh"])
    assert result["total_passwords"] == 4
    assert result["invalid_or_empty_count"] == 2
    assert result["unique_passwords"] == 2
