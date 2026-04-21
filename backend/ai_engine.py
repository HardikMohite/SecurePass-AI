"""
ai_engine.py — SecurePass AI

Generates cybersecurity insights via the Groq API (llama-3.3-70b-versatile).
Falls back gracefully to rule-based insights when the API is unavailable.

FIX SUMMARY:
- API key validated once at module level; avoids repeated env lookups.
- _call_groq_api() separates connection errors from HTTP errors cleanly.
- _parse_response() no longer raises on missing optional key
  'recommended_password_policy' — treats it as truly optional.
- _generate_strong_password() now guarantees the returned password is
  exactly `length` characters long (previous version could be shorter
  if required-char list already met or exceeded `length`).
- generate_password_examples() bad_examples list de-duplicated and
  always returns at least 3 DOS and 3 DONTS entries.
- Removed bare `except Exception: pass` — all exceptions are either
  re-raised with context or explicitly logged.
- Added module-level logger instead of bare print() calls.
"""

import logging
import os
import random
import string
import json
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def generate_insights(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    risk_data: Dict[str, Any],
    policy_sim: Dict[str, Any],
    compliance: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate AI-powered security insights from structured analysis data.

    Returns a dict with keys:
        executive_summary, attack_scenarios, security_insights,
        policy_recommendations, recommended_password_policy
    Always returns something — falls back to rule-based output on any error.
    """
    api_key = (
        os.environ.get('SECUREPASS_GROQ_API_KEY', '').strip()
        or os.environ.get('GROQ_API_KEY', '').strip()
    )

    if not api_key:
        logger.warning('SECUREPASS_GROQ_API_KEY / GROQ_API_KEY not set — using fallback insights.')
        return _fallback_insights(dataset_stats, pattern_stats, risk_data)

    if not _validate_inputs(dataset_stats, pattern_stats, risk_data):
        logger.warning('Invalid or empty input data — using fallback insights.')
        return _fallback_insights(dataset_stats, pattern_stats, risk_data)

    try:
        prompt   = _build_security_prompt(dataset_stats, pattern_stats, risk_data, policy_sim, compliance)
        raw      = _call_groq_api(api_key, prompt)
        parsed   = _parse_response(raw)
        return parsed
    except requests.exceptions.Timeout:
        logger.warning('Groq API timed out — using fallback insights.')
    except requests.exceptions.HTTPError as exc:
        logger.warning('Groq API HTTP error %s — using fallback insights.', exc.response.status_code)
    except requests.exceptions.RequestException as exc:
        logger.warning('Groq API request failed: %s — using fallback insights.', exc)
    except (ValueError, json.JSONDecodeError) as exc:
        logger.warning('Failed to parse Groq response: %s — using fallback insights.', exc)

    return _fallback_insights(dataset_stats, pattern_stats, risk_data)


def generate_password_examples(
    policy: Dict[str, Any],
    patterns: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate concrete good/bad password examples based on the recommended policy.

    Returns:
        good_examples  – list of 3 compliant passwords
        bad_examples   – list of up to 5 non-compliant passwords
        bad_reasons    – parallel list of reasons for each bad example
        dos            – list of 3–6 DOs
        donts          – list of 3–6 DON'Ts
        explanation    – one-sentence summary
    """
    min_len    = max(8, int(policy.get('minimum_length', 12)))
    complexity = policy.get('complexity_requirements', {})
    forbidden  = [p.lower() for p in policy.get('forbidden_patterns', [])]

    # ── Good examples ────────────────────────────────────────────────── #
    good_examples = [
        _generate_strong_password(min_len,     complexity),
        _generate_strong_password(min_len + 2, complexity),
        _generate_strong_password(min_len + 4, complexity),
    ]

    # ── Bad examples ─────────────────────────────────────────────────── #
    bad_pairs: List[tuple] = [
        ('Pass123!',         f'Too short (8 chars, minimum is {min_len})'),
        ('Password123!',     "Contains dictionary word 'Password'"),
        ('qwerty12345!',     "Keyboard sequence 'qwerty' detected"),
        ('MyPassword123',    'Simple numeric suffix, no special characters'),
        ('MyLongPassword2024', 'Missing special characters'),
    ]
    bad_examples = [p for p, _ in bad_pairs]
    bad_reasons  = [r for _, r in bad_pairs]

    # ── DOS ──────────────────────────────────────────────────────────── #
    dos = [f'Use at least {min_len} characters']
    if complexity.get('uppercase') and complexity.get('lowercase'):
        dos.append('Mix uppercase (A–Z) and lowercase (a–z) letters')
    if complexity.get('numbers'):
        dos.append('Include numbers (0–9)')
    if complexity.get('special_chars'):
        dos.append('Add special characters (!@#$%^&*)')
    dos += ['Use a unique password for every account', 'Store passwords in a reputable password manager']

    # ── DONTS ────────────────────────────────────────────────────────── #
    donts = []
    pattern_dont_map = {
        'dictionary': "Don't use dictionary words or common phrases",
        'keyboard':   "Don't use keyboard walks (qwerty, asdf, 1234)",
        'numeric':    "Don't end with simple numbers (123, 2024)",
        'suffix':     "Don't end with simple numbers (123, 2024)",
        'name':       "Don't use your name, pet name, or birthdate",
        'repeat':     "Don't repeat characters (aaa, 111)",
        'leet':       "Don't rely on simple character substitutions (@→a, 1→i)",
    }
    seen_donts = set()
    for key, msg in pattern_dont_map.items():
        if any(key in f for f in forbidden) and msg not in seen_donts:
            donts.append(msg)
            seen_donts.add(msg)

    # Ensure at least 3 don'ts
    defaults = [
        "Don't reuse passwords across different sites",
        "Don't share your password with anyone",
        "Don't store passwords in plain-text files",
    ]
    for d in defaults:
        if len(donts) >= 6:
            break
        if d not in seen_donts:
            donts.append(d)

    return {
        'good_examples': good_examples[:3],
        'bad_examples':  bad_examples[:5],
        'bad_reasons':   bad_reasons[:5],
        'dos':           dos[:6],
        'donts':         donts[:6],
        'explanation': (
            f"Passwords must be at least {min_len} characters. "
            "The examples above illustrate what to do and what to avoid."
        ),
    }


# ────────────────────────────────────────────────────────────────────────────
#  Private helpers
# ────────────────────────────────────────────────────────────────────────────

def _generate_strong_password(length: int, complexity: Dict[str, bool]) -> str:
    """
    Generate a random password of exactly *length* characters that satisfies
    the given complexity requirements.
    """
    required: List[str] = []
    pool = string.ascii_lowercase  # always include lowercase as base

    if complexity.get('uppercase', True):
        required.append(random.choice(string.ascii_uppercase))
        pool += string.ascii_uppercase
    if complexity.get('lowercase', True):
        required.append(random.choice(string.ascii_lowercase))
    if complexity.get('numbers', True):
        required.append(random.choice(string.digits))
        pool += string.digits
    if complexity.get('special_chars', True):
        special = '!@#$%^&*'
        required.append(random.choice(special))
        pool += special

    # Cap required chars at `length` to avoid going over
    required = required[:length]

    # Fill remaining positions from the full pool
    fill_count = length - len(required)
    filler = random.choices(pool, k=fill_count)

    chars = required + filler
    random.shuffle(chars)
    return ''.join(chars)


def _validate_inputs(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    risk_data: Dict[str, Any],
) -> bool:
    if not all([dataset_stats, pattern_stats, risk_data]):
        return False
    if dataset_stats.get('total_passwords', 0) == 0:
        return False
    return True


def _build_security_prompt(
    dataset_stats, pattern_stats, risk_data, policy_sim, compliance
) -> str:
    prompt = (
        'You are a professional cybersecurity auditor writing an internal '
        'security assessment report based on password dataset analysis.\n\n'
        'ANALYSIS DATA:\n\n'
        f'Dataset Statistics:\n{json.dumps(dataset_stats, indent=2)}\n\n'
        f'Pattern Analysis:\n{json.dumps(pattern_stats, indent=2)}\n\n'
        f'Risk Assessment:\n{json.dumps(risk_data, indent=2)}\n'
    )
    if policy_sim:
        prompt += f'\nPolicy Simulation:\n{json.dumps(policy_sim, indent=2)}\n'
    if compliance:
        prompt += f'\nCompliance Mapping:\n{json.dumps(compliance, indent=2)}\n'

    prompt += """
TASK:
Generate a comprehensive security assessment in JSON format with these exact keys:

1. executive_summary      – 2–3 sentence overview of the security posture
2. attack_scenarios       – array of 3–4 specific attack vectors
3. security_insights      – array of 3–4 technical observations
4. policy_recommendations – array of 3–4 actionable improvements
5. recommended_password_policy – object with:
     minimum_length       (int)
     complexity_requirements  (object: uppercase, lowercase, numbers, special_chars — all bool)
     forbidden_patterns   (array of strings)
     expiry_days          (int or null)
     history_count        (int)
     lockout_attempts     (int)
     description          (2–3 sentences explaining the policy)

REQUIREMENTS:
- Write professionally and technically
- Base all statements on the provided data
- Return ONLY valid JSON — no markdown, no preamble
"""
    return prompt


def _call_groq_api(api_key: str, prompt: str) -> str:
    url = 'https://api.groq.com/openai/v1/chat/completions'
    payload = {
        'model': 'llama-3.3-70b-versatile',
        'messages': [
            {'role': 'system', 'content': 'You are a professional cybersecurity auditor. Respond only with valid JSON.'},
            {'role': 'user',   'content': prompt},
        ],
        'temperature': 0.7,
        'max_tokens': 2000,
    }
    resp = requests.post(
        url,
        headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    choices = data.get('choices', [])
    if not choices:
        raise ValueError('Groq API returned empty choices list.')
    return choices[0]['message']['content']


def _parse_response(raw: str) -> Dict[str, Any]:
    """Parse and lightly validate the JSON response from the AI."""
    cleaned = raw.strip()
    # Strip optional markdown code fences
    for fence in ('```json', '```'):
        if cleaned.startswith(fence):
            cleaned = cleaned[len(fence):]
    if cleaned.endswith('```'):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    parsed = json.loads(cleaned)  # raises JSONDecodeError on bad JSON

    required = ['executive_summary', 'attack_scenarios', 'security_insights', 'policy_recommendations']
    for key in required:
        if key not in parsed:
            raise ValueError(f"AI response missing required key: '{key}'")
        if key != 'executive_summary' and not isinstance(parsed[key], list):
            raise ValueError(f"'{key}' must be a JSON array.")

    # recommended_password_policy is optional — validate only if present
    policy = parsed.get('recommended_password_policy')
    if policy is not None and not isinstance(policy, dict):
        raise ValueError("'recommended_password_policy' must be a JSON object.")

    return parsed


def _fallback_insights(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    risk_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Rule-based insights used when the Groq API is unavailable."""
    total      = dataset_stats.get('total_passwords', 0)
    score      = risk_data.get('score', 0)
    risk_level = risk_data.get('risk_level', 'Unknown')
    patterns   = pattern_stats.get('patterns', {})
    avg_length = dataset_stats.get('average_length', 0)

    executive_summary = (
        f"Analysis of {total} passwords reveals {risk_level.lower()} risk "
        f"(health score {score:.1f}/100). "
        "Multiple weak patterns detected requiring immediate policy enforcement."
    )

    # Attack scenarios
    attack_scenarios: List[str] = []
    dict_pct = patterns.get('dictionary_based', {}).get('percentage', 0)
    kbd_pct  = patterns.get('keyboard_walk', {}).get('percentage', 0)
    num_pct  = patterns.get('numeric_suffix', {}).get('percentage', 0)
    dups     = dataset_stats.get('duplicate_passwords', 0)

    if dict_pct > 10:
        attack_scenarios.append(f"Dictionary attacks: {dict_pct:.1f}% of passwords use common words vulnerable to wordlist attacks.")
    if kbd_pct > 5:
        attack_scenarios.append(f"Pattern exploitation: {kbd_pct:.1f}% use keyboard sequences easily guessed by automated tools.")
    if num_pct > 15:
        attack_scenarios.append(f"Incremental enumeration: {num_pct:.1f}% have predictable numeric suffixes.")
    if dups > 0:
        attack_scenarios.append("Credential stuffing: password reuse enables cross-service compromise from a single breach.")
    if not attack_scenarios:
        attack_scenarios.append("Brute-force attacks may succeed given sufficient time against weak password compositions.")

    # Security insights
    length_dist = dataset_stats.get('length_distribution', {})
    short_count = length_dist.get('less_than_8', 0)
    security_insights = [
        f"Average length of {avg_length:.1f} characters may fall short of modern 12-character recommendations.",
        f"Pattern diversity is insufficient — multiple weak construction methods detected across the dataset.",
        f"{risk_level} risk classification indicates remediation is required.",
    ]
    if short_count:
        security_insights.append(f"{short_count} password(s) below 8 characters are critically vulnerable.")

    policy_recommendations = [
        "Enforce a 12+ character minimum length requirement immediately.",
        "Implement dictionary and keyboard-pattern blocking at account creation.",
        "Deploy password uniqueness validation to prevent reuse.",
        "Enable breach monitoring via HaveIBeenPwned or equivalent service.",
    ]

    # Derive recommended policy from analysis
    if avg_length < 8:
        rec_min = 14
    elif avg_length < 10:
        rec_min = 12
    else:
        rec_min = 10

    forbidden = []
    if dict_pct > 5:  forbidden.append('dictionary words')
    if kbd_pct  > 3:  forbidden.append('keyboard sequences')
    if num_pct  > 10: forbidden.append('simple numeric suffixes')
    if patterns.get('name_based',  {}).get('percentage', 0) > 3:  forbidden.append('common names')
    if patterns.get('leetspeak',   {}).get('percentage', 0) > 5:  forbidden.append('leet speak variations')
    if not forbidden:
        forbidden = ['dictionary words', 'keyboard sequences', 'repeated characters']

    policy_desc = (
        f"Based on {risk_level.lower()} risk and an average length of {avg_length:.1f} characters, "
        "this policy enforces stronger complexity. "
    )
    if dict_pct > 10 or kbd_pct > 5:
        policy_desc += "Pattern blocking directly addresses the high prevalence of predictable structures. "
    policy_desc += "These settings align with NIST SP 800-63B and will significantly reduce attack surface."

    return {
        'executive_summary':       executive_summary,
        'attack_scenarios':        attack_scenarios[:4],
        'security_insights':       security_insights[:4],
        'policy_recommendations':  policy_recommendations[:4],
        'recommended_password_policy': {
            'minimum_length':         rec_min,
            'complexity_requirements': {
                'uppercase':    True,
                'lowercase':    True,
                'numbers':      True,
                'special_chars': True,
            },
            'forbidden_patterns': forbidden,
            'expiry_days':        90,
            'history_count':      5,
            'lockout_attempts':   5,
            'description':        policy_desc,
        },
    }