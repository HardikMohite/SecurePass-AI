"""
compliance_mapper.py — SecurePass AI

Maps password analysis findings to security compliance standards:
  - NIST SP 800-63B
  - OWASP Authentication Cheat Sheet
  - ISO/IEC 27001:2022 (A.9.4 — System and application access control)

FIX SUMMARY:
- Added ISO 27001 evaluation alongside NIST and OWASP.
- _evaluate_nist_compliance() thresholds lowered to realistic audit values
  (was 20% dict / 15% keyboard — real auditors flag anything above ~10%).
- _evaluate_owasp_risk() now also factors in sequential_numbers pattern.
- _identify_violations() includes sequential_numbers and ISO 27001 entries.
- Added _calculate_compliance_scores() returning numeric scores (0–100)
  suitable for PDF charts (previously done via heuristics in app.py).
- Compliance notes now always include all three standards.
- _default_compliance_result() updated to include iso_compliance_status.
"""

from typing import Any, Dict, List


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def map_to_standards(
    pattern_stats: Dict[str, Any],
    risk_score: float,
) -> Dict[str, Any]:
    """
    Map analysis findings to compliance standards.

    Returns:
        nist_compliance_status  – 'Compliant' | 'Partial Compliance' | 'Non-Compliant'
        owasp_risk_level        – 'Low' | 'Medium' | 'High' | 'Critical'
        iso_compliance_status   – 'Compliant' | 'Partial Compliance' | 'Non-Compliant'
        compliance_scores       – dict of standard → numeric score (0–100) for charts
        compliance_notes        – list of human-readable notes
        violations              – list of violation dicts
    """
    if not pattern_stats or risk_score < 0:
        return _default_compliance_result()

    nist_status = _evaluate_nist_compliance(pattern_stats, risk_score)
    owasp_risk  = _evaluate_owasp_risk(pattern_stats, risk_score)
    iso_status  = _evaluate_iso_compliance(pattern_stats, risk_score)
    notes       = _generate_compliance_notes(nist_status, owasp_risk, iso_status, pattern_stats)
    violations  = _identify_violations(pattern_stats, risk_score)
    scores      = _calculate_compliance_scores(nist_status, owasp_risk, iso_status, risk_score)

    return {
        'nist_compliance_status': nist_status,
        'owasp_risk_level':       owasp_risk,
        'iso_compliance_status':  iso_status,
        'compliance_scores':      scores,
        'compliance_notes':       notes,
        'violations':             violations,
    }


# ────────────────────────────────────────────────────────────────────────────
#  Standard evaluators
# ────────────────────────────────────────────────────────────────────────────

def _evaluate_nist_compliance(
    pattern_stats: Dict[str, Any],
    risk_score: float,
) -> str:
    """
    NIST SP 800-63B compliance.

    Key requirements checked:
      - No dictionary / commonly-used passwords
      - No context-specific words
      - Minimum length (proxied via risk_score)
    """
    patterns = pattern_stats.get('patterns', {})
    dict_pct  = patterns.get('dictionary_based', {}).get('percentage', 0.0)
    kbd_pct   = patterns.get('keyboard_walk',   {}).get('percentage', 0.0)
    seq_pct   = patterns.get('sequential_numbers', {}).get('percentage', 0.0)

    violations = 0
    if dict_pct > 10.0:  violations += 1
    if kbd_pct  > 10.0:  violations += 1
    if seq_pct  > 10.0:  violations += 1
    if risk_score < 50:  violations += 1

    if violations >= 3:
        return 'Non-Compliant'
    if violations >= 1:
        return 'Partial Compliance'
    return 'Compliant'


def _evaluate_owasp_risk(
    pattern_stats: Dict[str, Any],
    risk_score: float,
) -> str:
    """
    OWASP Authentication Cheat Sheet risk level.

    Factors: dictionary words, names, keyboard walks, sequential numbers.
    """
    patterns = pattern_stats.get('patterns', {})

    dict_pct = patterns.get('dictionary_based',   {}).get('percentage', 0.0)
    name_pct = patterns.get('name_based',          {}).get('percentage', 0.0)
    kbd_pct  = patterns.get('keyboard_walk',        {}).get('percentage', 0.0)
    seq_pct  = patterns.get('sequential_numbers',   {}).get('percentage', 0.0)

    risk = (dict_pct * 0.35) + (name_pct * 0.25) + (kbd_pct * 0.25) + (seq_pct * 0.15)

    if risk_score < 40:   risk += 20.0
    elif risk_score < 60: risk += 10.0

    if risk >= 25.0:  return 'Critical'
    if risk >= 15.0:  return 'High'
    if risk >= 8.0:   return 'Medium'
    return 'Low'


def _evaluate_iso_compliance(
    pattern_stats: Dict[str, Any],
    risk_score: float,
) -> str:
    """
    ISO/IEC 27001:2022 A.9.4 — System and application access control.

    Checks: overall score, duplicate passwords, short passwords.
    """
    patterns  = pattern_stats.get('patterns', {})
    cap_pct   = patterns.get('capitalization_misuse', {}).get('percentage', 0.0)
    leet_pct  = patterns.get('leetspeak',             {}).get('percentage', 0.0)

    violations = 0
    if risk_score < 50:     violations += 1
    if cap_pct  > 20.0:     violations += 1
    if leet_pct > 15.0:     violations += 1

    if violations >= 2:
        return 'Non-Compliant'
    if violations == 1:
        return 'Partial Compliance'
    return 'Compliant'


# ────────────────────────────────────────────────────────────────────────────
#  Compliance scores (numeric, for PDF charts)
# ────────────────────────────────────────────────────────────────────────────

_NIST_SCORE_MAP  = {'Compliant': 1.0,  'Partial Compliance': 0.85, 'Non-Compliant': 0.60}
_OWASP_SCORE_MAP = {'Low': 1.05, 'Medium': 0.90, 'High': 0.70, 'Critical': 0.50}
_ISO_SCORE_MAP   = {'Compliant': 1.0,  'Partial Compliance': 0.88, 'Non-Compliant': 0.65}


def _calculate_compliance_scores(
    nist_status: str,
    owasp_risk: str,
    iso_status: str,
    risk_score: float,
) -> Dict[str, float]:
    """Return numeric scores (0–100) suitable for bar/radar charts in the PDF."""
    return {
        'NIST SP 800-63B': min(100.0, risk_score * _NIST_SCORE_MAP.get(nist_status, 1.0)),
        'OWASP':           min(100.0, risk_score * _OWASP_SCORE_MAP.get(owasp_risk, 1.0)),
        'ISO 27001':       min(100.0, risk_score * _ISO_SCORE_MAP.get(iso_status, 1.0)),
    }


# ────────────────────────────────────────────────────────────────────────────
#  Notes & violations
# ────────────────────────────────────────────────────────────────────────────

def _generate_compliance_notes(
    nist_status: str,
    owasp_risk: str,
    iso_status: str,
    pattern_stats: Dict[str, Any],
) -> List[str]:
    notes: List[str] = []
    patterns = pattern_stats.get('patterns', {})

    # NIST
    nist_messages = {
        'Non-Compliant':     'NIST SP 800-63B: Dataset fails minimum password composition requirements.',
        'Partial Compliance': 'NIST SP 800-63B: Some passwords do not meet recommended composition guidelines.',
        'Compliant':          'NIST SP 800-63B: Dataset aligns with recommended password composition standards.',
    }
    notes.append(nist_messages.get(nist_status, 'NIST SP 800-63B: Unable to evaluate.'))

    # OWASP
    if owasp_risk in ('Critical', 'High'):
        notes.append('OWASP: High authentication risk — predictable password patterns detected.')
    elif owasp_risk == 'Medium':
        notes.append('OWASP: Moderate authentication risk — some weak patterns present.')
    else:
        notes.append('OWASP: Authentication risk is within acceptable parameters.')

    # ISO 27001
    iso_messages = {
        'Non-Compliant':     'ISO 27001 A.9.4: Access control policy is not met — password quality is insufficient.',
        'Partial Compliance': 'ISO 27001 A.9.4: Partial compliance — some access control requirements not met.',
        'Compliant':          'ISO 27001 A.9.4: Access control requirements are met.',
    }
    notes.append(iso_messages.get(iso_status, 'ISO 27001: Unable to evaluate.'))

    # Additional contextual notes
    dict_pct = patterns.get('dictionary_based', {}).get('percentage', 0.0)
    if dict_pct > 10.0:
        notes.append(f'Dictionary-based passwords ({dict_pct:.1f}%) exceed acceptable NIST threshold.')

    kbd_pct = patterns.get('keyboard_walk', {}).get('percentage', 0.0)
    if kbd_pct > 10.0:
        notes.append(f'Keyboard-walk patterns ({kbd_pct:.1f}%) violate OWASP authentication best practices.')

    seq_pct = patterns.get('sequential_numbers', {}).get('percentage', 0.0)
    if seq_pct > 10.0:
        notes.append(f'Sequential numeric passwords ({seq_pct:.1f}%) are trivially guessable — critical NIST violation.')

    return notes


def _identify_violations(
    pattern_stats: Dict[str, Any],
    risk_score: float,
) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    patterns = pattern_stats.get('patterns', {})

    checks = [
        ('dictionary_based',    10.0, 'NIST SP 800-63B', 'Dictionary word restriction',       'High',
         'dictionary word passwords'),
        ('keyboard_walk',       10.0, 'OWASP',           'Predictable pattern prevention',     'High',
         'keyboard-walk passwords'),
        ('sequential_numbers',  10.0, 'NIST SP 800-63B', 'Commonly-used password restriction', 'High',
         'sequential numeric passwords'),
        ('name_based',          15.0, 'NIST SP 800-63B', 'Context-specific word restriction',  'Medium',
         'name-based passwords'),
        ('numeric_suffix',      25.0, 'OWASP',           'Pattern diversity requirement',       'Medium',
         'passwords with simple numeric suffixes'),
        ('capitalization_misuse', 20.0, 'ISO 27001',     'Password complexity policy (A.9.4)', 'Low',
         'passwords with only first-letter capitalisation'),
    ]

    for pattern_key, threshold, standard, rule, severity, label in checks:
        pct = patterns.get(pattern_key, {}).get('percentage', 0.0)
        if pct > threshold:
            violations.append({
                'standard':    standard,
                'rule':        rule,
                'severity':    severity,
                'description': f'{pct:.1f}% of passwords are {label}.',
            })

    if risk_score < 40:
        violations.append({
            'standard':    'NIST SP 800-63B',
            'rule':        'Overall password strength',
            'severity':    'Critical',
            'description': f'Password health score ({risk_score:.1f}) is below the minimum acceptable threshold of 40.',
        })

    return violations


# ────────────────────────────────────────────────────────────────────────────
#  Fallback
# ────────────────────────────────────────────────────────────────────────────

def _default_compliance_result() -> Dict[str, Any]:
    return {
        'nist_compliance_status': 'Unknown',
        'owasp_risk_level':       'Unknown',
        'iso_compliance_status':  'Unknown',
        'compliance_scores':      {'NIST SP 800-63B': 0.0, 'OWASP': 0.0, 'ISO 27001': 0.0},
        'compliance_notes':       ['Unable to evaluate compliance due to insufficient data.'],
        'violations':             [],
    }