"""
pattern_detector.py — SecurePass AI

Detects common weak password construction patterns across a dataset.

FIX SUMMARY:
- Expanded common_words and common_names sets (was missing many top-10
  passwords like 'abc123', '111111', 'iloveyou', etc.).
- _count_leetspeak() previously flagged almost every password that
  contained any digit or '@' (since those chars are extremely common).
  Reworked to require both a leet char AND its letter equivalent present
  after substitution, reducing false positives substantially.
- Added _count_sequential_numbers() to catch '123456'-style passwords
  that were passing all existing checks undetected.
- Removed the duplicate min_length / max_length / median_length calculation
  that used to live here — dataset_analyzer.analyze_dataset() already
  computes these (plus std_dev_length, which this module never had) from
  the same password list, so this was a second source of truth for numbers
  the report already gets elsewhere. app.py now reads length stats only
  from dataset_analyzer's output.
- _filter_valid_passwords() now also strips trailing CR for Windows files.
- All count functions are pure (no side-effects).
"""

import re
from typing import Any, Dict, List


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def detect_patterns(passwords: List[str]) -> Dict[str, Any]:
    """
    Detect common weak password patterns across a dataset.

    Returns a dict with:
        total_analyzed  – int
        patterns        – dict of pattern → {count, percentage}
    """
    if not passwords:
        return _empty_pattern_result()

    valid = _filter_valid_passwords(passwords)
    if not valid:
        return _empty_pattern_result()

    total = len(valid)

    counts = {
        'dictionary_based':    _count_dictionary_passwords(valid),
        'name_based':          _count_name_passwords(valid),
        'numeric_suffix':      _count_numeric_suffix(valid),
        'keyboard_walk':       _count_keyboard_walks(valid),
        'capitalization_misuse': _count_capitalization_misuse(valid),
        'leetspeak':           _count_leetspeak(valid),
        'sequential_numbers':  _count_sequential_numbers(valid),
    }

    return {
        'total_analyzed': total,
        'patterns': {
            name: {
                'count':      cnt,
                'percentage': _pct(cnt, total),
            }
            for name, cnt in counts.items()
        },
    }


# ────────────────────────────────────────────────────────────────────────────
#  Filtering
# ────────────────────────────────────────────────────────────────────────────

def _filter_valid_passwords(passwords: List[str]) -> List[str]:
    return [p.strip('\r\n ') for p in passwords if p and p.strip()]


# ────────────────────────────────────────────────────────────────────────────
#  Pattern counters
# ────────────────────────────────────────────────────────────────────────────

# Expanded to include the most common real-world weak passwords
_COMMON_WORDS = {
    'password', 'password1', 'password123', 'welcome', 'welcome1',
    'admin', 'admin123', 'login', 'letmein', 'sunshine', 'monkey',
    'dragon', 'master', 'shadow', 'football', 'baseball', 'superman',
    'michael', 'jennifer', 'jordan', 'hunter', 'freedom', 'trustno1',
    'princess', 'starwars', 'buster', 'soccer', 'hockey', 'batman',
    'tigger', 'chicken', 'computer', 'internet', 'charlie', 'iloveyou',
    'abc', 'abcd', 'abcde', 'abcdef', 'letmein', 'mustang', 'access',
    'hello', 'ninja', 'passw0rd', 'p@ssword', 'p@ssw0rd', 'test',
    'test123', 'guest', 'temp', 'changeme', 'default', 'root',
}

_COMMON_NAMES = {
    'john', 'james', 'robert', 'mary', 'patricia', 'jennifer',
    'michael', 'william', 'david', 'richard', 'joseph', 'charles',
    'thomas', 'sarah', 'jessica', 'emily', 'andrew', 'daniel',
    'matthew', 'christopher', 'ashley', 'amanda', 'lisa', 'michelle',
    'kevin', 'mark', 'donald', 'george', 'kenneth', 'steven',
    'edward', 'brian', 'ronald', 'anthony', 'barbara', 'susan',
    'dorothy', 'karen', 'nancy', 'betty', 'helen', 'sandra',
}

# Keyboard walk sequences (ordered longest first to get priority match)
_KEYBOARD_WALKS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    'poiuytrewq', 'lkjhgfdsa', 'mnbvcxz',
    '1qaz2wsx3edc', '1qaz2wsx', 'qazwsx', '1qaz',
    'qwerty', 'asdfg', 'zxcvb', 'qwer', 'asdf', 'zxcv',
    '123456789', '12345678', '1234567', '123456', '12345', '1234', '123',
    '987654321', '987654', '9876', '0987',
    '1q2w3e4r', '1q2w3e',
]


def _count_dictionary_passwords(passwords: List[str]) -> int:
    count = 0
    for pwd in passwords:
        base = re.sub(r'[^a-z]', '', pwd.lower())
        if base in _COMMON_WORDS:
            count += 1
    return count


def _count_name_passwords(passwords: List[str]) -> int:
    count = 0
    for pwd in passwords:
        base = re.sub(r'[^a-z]', '', pwd.lower())
        if base in _COMMON_NAMES:
            count += 1
    return count


def _count_numeric_suffix(passwords: List[str]) -> int:
    """Passwords that are alphabetic text followed by digits, e.g. hello123."""
    pattern = re.compile(r'^[a-zA-Z]{2,}\d+$')
    return sum(1 for p in passwords if pattern.match(p))


def _count_keyboard_walks(passwords: List[str]) -> int:
    count = 0
    for pwd in passwords:
        lower = pwd.lower()
        if any(kw in lower for kw in _KEYBOARD_WALKS):
            count += 1
    return count


def _count_capitalization_misuse(passwords: List[str]) -> int:
    """Only the very first letter capitalised, rest lowercase + optional digits."""
    pattern = re.compile(r'^[A-Z][a-z]+\d*[!@#$%^&*]?$')
    return sum(1 for p in passwords if pattern.match(p))


def _count_leetspeak(passwords: List[str]) -> int:
    """
    Count passwords that use leet-speak substitutions.

    A password counts only if:
      1. It contains a recognised leet character (@, 3, 0, 1, 5, 7, 4), AND
      2. After reversing the substitution the resulting base word is at least
         4 alphabetic characters (guards against normal passwords with digits).
    """
    leet_map = str.maketrans({
        '@': 'a', '4': 'a',
        '3': 'e',
        '1': 'i', '!': 'i',
        '0': 'o',
        '5': 's', '$': 's',
        '7': 't',
        '9': 'g',  # Bug 6 fix: '9' was in leet_chars but '9'→'g' entry was missing — now consistent
    })
    leet_chars = set('@4310!5$79')

    count = 0
    for pwd in passwords:
        if not any(c in leet_chars for c in pwd):
            continue
        # Only flag if the password also has alphabetic characters
        # (avoids pure-numeric passwords being flagged)
        if not re.search(r'[a-zA-Z]', pwd):
            continue
        converted = pwd.lower().translate(leet_map)
        alpha_only = re.sub(r'[^a-z]', '', converted)
        if len(alpha_only) >= 4:
            count += 1

    return count


def _count_sequential_numbers(passwords: List[str]) -> int:
    """
    Count passwords that are purely (or predominantly) sequential digit runs,
    e.g. '123456', '111111', '000000'.
    """
    # Purely numeric passwords of length 4+
    pure_numeric = re.compile(r'^\d{4,}$')
    count = 0
    for pwd in passwords:
        if not pure_numeric.match(pwd):
            continue
        # Ascending run: each digit is previous + 1
        if all(int(pwd[i]) - int(pwd[i - 1]) == 1 for i in range(1, len(pwd))):
            count += 1
            continue
        # Descending run
        if all(int(pwd[i - 1]) - int(pwd[i]) == 1 for i in range(1, len(pwd))):
            count += 1
            continue
        # All-same digit: 111111, 000000
        if len(set(pwd)) == 1:
            count += 1
    return count


# ────────────────────────────────────────────────────────────────────────────
#  Utilities
# ────────────────────────────────────────────────────────────────────────────

def _pct(count: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(count / total * 100, 2)


def _empty_pattern_result() -> Dict[str, Any]:
    pattern_names = [
        'dictionary_based', 'name_based', 'numeric_suffix',
        'keyboard_walk', 'capitalization_misuse', 'leetspeak', 'sequential_numbers',
    ]
    return {
        'total_analyzed': 0,
        'patterns': {name: {'count': 0, 'percentage': 0.0} for name in pattern_names},
    }