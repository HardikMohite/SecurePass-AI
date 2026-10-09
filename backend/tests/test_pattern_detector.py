"""
Unit test for backend/pattern_detector.py — detect_patterns() against a
small, fixed input list. Expected counts below were derived by tracing
the actual pattern-matching logic in pattern_detector.py for each
password (not just eyeballing the names), since several counters overlap
on the same password:

    "password"    -> exact hit in _COMMON_WORDS               -> dictionary_based
    "qwerty123"   -> contains keyboard-walk substring "qwerty" -> keyboard_walk
                     letters-then-digits shape                 -> numeric_suffix
                     digit '1' is a leet char and "qwertyie"
                     (leet-reversed, digit '2' dropped) is
                     8 alpha chars                              -> leetspeak
    "Sunrise7"    -> single leading capital + lower + digit    -> capitalization_misuse
                     letters-then-digits shape                 -> numeric_suffix
                     digit '7' is a leet char ('7'->'t') and
                     "sunriset" is 8 alpha chars                -> leetspeak
    "123456"      -> ascending digit run                       -> sequential_numbers
                     "123456" is also literally one of the
                     keyboard-walk entries (numeric-row walks
                     are included in that list)                 -> keyboard_walk
    "Tr0ub4dor"   -> leet substitution ('0'->'o', '4'->'a') and
                     "troubador" is 9 alpha chars                -> leetspeak

So: dictionary_based=1, keyboard_walk=2, numeric_suffix=2,
capitalization_misuse=1, leetspeak=3, sequential_numbers=1, name_based=0.
"""
from pattern_detector import detect_patterns

PASSWORDS = ["password", "qwerty123", "Sunrise7", "123456", "Tr0ub4dor"]


def test_detect_patterns_total():
    result = detect_patterns(PASSWORDS)
    assert result["total_analyzed"] == 5


def test_detect_patterns_dictionary_based():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["dictionary_based"]["count"] == 1


def test_detect_patterns_keyboard_walk():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["keyboard_walk"]["count"] == 2


def test_detect_patterns_numeric_suffix():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["numeric_suffix"]["count"] == 2


def test_detect_patterns_sequential_numbers():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["sequential_numbers"]["count"] == 1


def test_detect_patterns_leetspeak():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["leetspeak"]["count"] == 3


def test_detect_patterns_capitalization_misuse():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["capitalization_misuse"]["count"] == 1


def test_detect_patterns_name_based_no_matches_in_fixture():
    result = detect_patterns(PASSWORDS)
    assert result["patterns"]["name_based"]["count"] == 0


def test_detect_patterns_empty_input_returns_zeroed_result():
    result = detect_patterns([])
    assert result["total_analyzed"] == 0
    assert all(p["count"] == 0 for p in result["patterns"].values())
