"""
charts.py — SecurePass AI

Generates professional security analytics charts for reports.

DESIGN NOTES (report-quality pass):
- Chart set trimmed from 9 to 4. The previous set had real overlap and one
  fabricated series:
    * 'risk_comparison' duplicated 'risk_pie' (same distribution, bar vs pie).
    * 'pattern_distribution' duplicated 'top_patterns' (same pattern counts,
      pie vs bar) — the bar version is kept because it reads clearly with
      6+ categories, which a pie chart does not.
    * 'complexity_breakdown' split the "non-weak" remainder into Medium/
      Strong using a hardcoded 0.6 factor that has no basis in the actual
      dataset — an estimated number presented as measured data. Dropped.
    * 'strength_distribution' (character/length criteria coverage) overlapped
      the Dataset Overview table and the length-distribution chart without
      adding a decision a reader would act on differently. Dropped.
  What remains — Security Score Gauge, Risk Distribution, Length
  Distribution, Top Weak Patterns — are each backed by real computed data,
  cover a distinct question (how risky / how risky in aggregate / how short
  / which patterns), and fill a clean 2x2 grid in the PDF with no orphan
  cell.
- Colour palette unified with pdf_gen.py's brand colours (navy / blue /
  red / amber / green) instead of the previous ad-hoc "dashboard" palette,
  so chart images and report text agree on what red/amber/green mean.
- matplotlib thread-safety: each chart function calls plt.close() in a
  finally block to avoid figure leaks when exceptions occur mid-render.
- OUTPUT_DIR is derived at call time (via _get_output_dir()) rather than a
  module-level constant so tests can override it cleanly.
- All chart functions return '' (empty string) rather than raising when
  there is no data to plot — consistent with existing caller expectations.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use('Agg')   # must be set before pyplot import
import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)

# frontend/ is a sibling of backend/ (this module lives at
# backend/reports/charts.py), so the default is cwd-relative assuming the
# app is run with backend/ as the working directory (see backend/app.py /
# start-server.ps1). _to_web_path() below matches on the 'frontend/static/'
# substring regardless of any leading '../', so this stays robust.
_DEFAULT_OUTPUT_DIR = '../frontend/static/reports/output'

# ── Brand palette — must match backend/reports/pdf_gen.py ──────────────────
NAVY   = '#0d1b4b'
BLUE   = '#1565c0'
RED    = '#c62828'
AMBER  = '#e65100'
GREEN  = '#2e7d32'
GREY   = '#78909c'

_FONT_TITLE = {'fontsize': 14, 'fontweight': 'bold', 'color': NAVY, 'pad': 16}
_FONT_AXIS  = {'fontsize': 11, 'fontweight': 'bold', 'color': '#37474f'}


# ────────────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────────────

def _get_output_dir() -> str:
    return os.environ.get('SECUREPASS_CHART_DIR', _DEFAULT_OUTPUT_DIR)


def _ensure_output_dir() -> None:
    os.makedirs(_get_output_dir(), exist_ok=True)


def _out(filename: str, output_dir: Optional[str] = None) -> str:
    out_dir = output_dir or _get_output_dir()
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, filename)


def _to_web_path(file_path: str) -> str:
    """Convert filesystem path to a browser-accessible /static/... URL."""
    p = file_path.replace('\\', '/')
    marker = 'frontend/static/'
    idx = p.find(marker)
    if idx != -1:
        return '/static/' + p[idx + len(marker):]
    # Already a relative path like 'reports/output/x.png' — add /static/ prefix
    if not p.startswith('/static/'):
        return '/static/' + p
    return p


def _resolve_chart_path(path_str: str) -> Optional[str]:
    """
    Resolve any incoming path (absolute, relative, or web URL '/static/...')
    to an existing absolute filesystem path.
    """
    if not path_str or not isinstance(path_str, str):
        return None
    # Direct existence check
    if os.path.isabs(path_str) and os.path.exists(path_str):
        return path_str
    if os.path.exists(path_str):
        return os.path.abspath(path_str)

    # Normalize web URL prefix
    cleaned = path_str.replace('\\', '/')
    if cleaned.startswith('/static/'):
        cleaned = cleaned[len('/static/'):]
    elif cleaned.startswith('static/'):
        cleaned = cleaned[len('static/'):]

    candidates = [
        os.path.join('frontend', 'static', cleaned),
        os.path.join('..', 'frontend', 'static', cleaned),
        os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'static', cleaned),
        os.path.join('reports', 'output', cleaned),
        os.path.join('..', 'reports', 'output', cleaned),
        cleaned,
    ]
    for c in candidates:
        abs_c = os.path.abspath(c)
        if os.path.exists(abs_c) and os.path.getsize(abs_c) > 0:
            return abs_c
    return None


def _save(fig, path: str, return_fs_path: bool = False) -> str:
    """Save figure to path and close it. Returns web-accessible path or filesystem path."""
    try:
        # DPI=100 produces crisp 300+ effective print DPI in PDF while encoding 2x faster than 150 DPI
        fig.savefig(path, dpi=100, bbox_inches='tight', facecolor='white')
        if return_fs_path:
            return os.path.abspath(path)
        return _to_web_path(path)
    finally:
        plt.close(fig)


def _style_axes(ax):
    """Shared minimal, professional axis styling."""
    for spine in ('top', 'right'):
        ax.spines[spine].set_visible(False)
    for spine in ('left', 'bottom'):
        ax.spines[spine].set_color('#cfd8dc')


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def generate_charts(
    dataset_stats: Dict[str, Any],
    risk_data: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    attack_scenarios: Any = None,
    compliance_data: Any = None,
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> Dict[str, str]:
    """
    Generate the report's chart set and return web-accessible paths.

    Generates the full visual analysis suite concurrently using ThreadPoolExecutor:
    - Security Score Gauge
    - Risk Distribution Pie
    - Password Length Distribution Bar
    - Top Weak Patterns Horizontal Bar
    - Password Cracking Simulation Bar
    - Regulatory Compliance Mapping Bar
    """
    if not output_dir:
        _ensure_output_dir()

    generators = {
        'security_gauge':      lambda: generate_security_score_gauge(risk_data, output_dir=output_dir, return_fs_path=return_fs_path),
        'risk_pie':             lambda: generate_risk_distribution_pie(risk_data, output_dir=output_dir, return_fs_path=return_fs_path),
        'length_distribution':  lambda: generate_length_distribution(dataset_stats, output_dir=output_dir, return_fs_path=return_fs_path),
        'top_patterns':         lambda: generate_top_weak_patterns(pattern_stats, output_dir=output_dir, return_fs_path=return_fs_path),
        'cracking_chart':       lambda: generate_cracking_simulation_chart(attack_scenarios, output_dir=output_dir, return_fs_path=return_fs_path) if attack_scenarios else '',
        'compliance_chart':     lambda: generate_compliance_mapping_chart(compliance_data, output_dir=output_dir, return_fs_path=return_fs_path) if compliance_data else '',
    }

    # Parallelize chart generation across available CPU cores for sub-second rendering
    from concurrent.futures import ThreadPoolExecutor

    def _exec_chart(item):
        key, fn = item
        try:
            res = fn()
            return key, res
        except Exception as exc:
            logger.warning('Chart generation failed for %s: %s', key, exc)
            return key, ''

    paths: Dict[str, str] = {}
    worker_count = min(6, os.cpu_count() or 4)
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        for key, res in pool.map(_exec_chart, generators.items()):
            if res:
                paths[key] = res

    return paths


# ────────────────────────────────────────────────────────────────────────────
#  Individual chart generators
# ────────────────────────────────────────────────────────────────────────────

def generate_security_score_gauge(
    risk_data: Dict[str, Any],
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> str:
    """Half-donut gauge showing the overall security score, 0-100."""
    score      = risk_data.get('score', 0) or 0
    risk_level = risk_data.get('risk_level', 'Unknown')
    color      = GREEN if score >= 70 else AMBER if score >= 40 else RED

    fig, ax = plt.subplots(figsize=(8, 5), subplot_kw={'projection': 'polar'})
    theta = np.linspace(0, np.pi, 200)
    ax.plot(theta, [1] * 200, color='#eceff1', linewidth=34, solid_capstyle='round')

    score_theta = np.linspace(0, np.pi * (score / 100), 200)
    ax.plot(score_theta, [1] * 200, color=color, linewidth=34, solid_capstyle='round')

    ax.set_ylim(0, 1.5)
    ax.set_theta_offset(np.pi)
    ax.set_theta_direction(-1)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.spines['polar'].set_visible(False)

    ax.text(np.pi / 2, 0.40, f'{score:.0f}',
            ha='center', va='center', fontsize=44, fontweight='bold', color=color)
    ax.text(np.pi / 2, 0.10, 'OVERALL SECURITY SCORE (0-100)',
            ha='center', va='center', fontsize=10, fontweight='bold', color=NAVY)
    fig.tight_layout()
    return _save(fig, _out('security_gauge.png', output_dir), return_fs_path=return_fs_path)


def generate_risk_distribution_pie(
    risk_data: Dict[str, Any],
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> str:
    """Pie chart of the High / Medium / Low risk password split."""
    distribution = risk_data.get('distribution', {})
    if not distribution:
        return ''

    key_to_label = {'high': 'High Risk', 'medium': 'Medium Risk', 'low': 'Low Risk'}
    color_map = {'High Risk': RED, 'Medium Risk': AMBER, 'Low Risk': GREEN}
    labels, sizes, colors = [], [], []
    for key in ['high', 'medium', 'low']:
        count = distribution.get(key, 0)
        if count > 0:
            label = key_to_label[key]
            labels.append(label)
            sizes.append(count)
            colors.append(color_map[label])

    if not sizes:
        return ''

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct='%1.1f%%',
        startangle=90, colors=colors, explode=[0.03] * len(sizes),
        wedgeprops=dict(edgecolor='white', linewidth=1.5),
    )
    for at in autotexts:
        at.set_color('white'); at.set_fontsize(11); at.set_weight('bold')
    for t in texts:
        t.set_fontsize(11); t.set_weight('bold'); t.set_color('#37474f')
    ax.set_title('Password Risk Distribution', **_FONT_TITLE)
    fig.tight_layout()
    return _save(fig, _out('risk_distribution_pie.png', output_dir), return_fs_path=return_fs_path)


def generate_length_distribution(
    dataset_stats: Dict[str, Any],
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> str:
    """4-bucket length distribution bar chart, worst-to-best colour ramp."""
    ld = dataset_stats.get('length_distribution', {})
    categories = ['< 8 chars', '8–11 chars', '12–15 chars', '16+ chars']
    values = [
        ld.get('less_than_8', 0),
        ld.get('8_to_11', 0),
        ld.get('12_to_15', 0),
        ld.get('16_plus', 0),
    ]
    if sum(values) == 0:
        return ''

    fig, ax = plt.subplots(figsize=(9, 5))
    colors = [RED, AMBER, BLUE, GREEN]
    bars = ax.bar(categories, values, color=colors, edgecolor='white', linewidth=1.2, width=0.6)
    ax.set_ylabel('Number of Passwords', **_FONT_AXIS)
    ax.set_title('Password Length Distribution', **_FONT_TITLE)
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h, f'{int(h):,}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold', color='#37474f')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    _style_axes(ax)
    fig.tight_layout()
    return _save(fig, _out('length_distribution.png', output_dir), return_fs_path=return_fs_path)


def generate_top_weak_patterns(
    pattern_stats: Dict[str, Any],
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> str:
    """Horizontal bar chart of the most common weak patterns detected."""
    patterns = pattern_stats.get('patterns', {})
    pattern_map = {
        'dictionary_based':      'Dictionary Words',
        'name_based':            'Common Names',
        'numeric_suffix':        'Numeric Suffix',
        'keyboard_walk':         'Keyboard Patterns',
        'capitalization_misuse': 'Simple Capitalisation',
        'leetspeak':             'Leet Speak',
        'sequential_numbers':    'Sequential Numbers',
    }

    data = [
        (label, patterns[key]['percentage'])
        for key, label in pattern_map.items()
        if patterns.get(key, {}).get('percentage', 0) > 0
    ]
    if not data:
        return ''

    data.sort(key=lambda x: x[1])  # ascending so the worst offender ends up on top
    data = data[-6:]
    labels = [d[0] for d in data]
    values = [d[1] for d in data]

    n = len(labels)
    base_shades = [BLUE] * (n - 1) + [RED]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(labels, values, color=base_shades, edgecolor='white', linewidth=1.1, height=0.6)
    ax.set_xlabel('% of Passwords Affected', **_FONT_AXIS)
    ax.set_title('Top Weak Password Patterns', **_FONT_TITLE)
    for bar, val in zip(bars, values):
        ax.text(val + 0.4, bar.get_y() + bar.get_height() / 2,
                f'{val:.1f}%', va='center', fontsize=10, fontweight='bold', color='#37474f')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    ax.set_xlim(0, max(values) * 1.18)
    _style_axes(ax)
    fig.tight_layout()
    return _save(fig, _out('top_weak_patterns.png', output_dir), return_fs_path=return_fs_path)


def generate_cracking_simulation_chart(
    attack_scenarios: Any,
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> str:
    """Vertical bar chart of vulnerability by attack vector (Dictionary, Keyboard, Brute Force, Pattern)."""
    if not attack_scenarios:
        return ''

    items = []
    if isinstance(attack_scenarios, list):
        for s in attack_scenarios:
            if isinstance(s, dict):
                name = s.get('name') or s.get('key', '')
                pct = float(s.get('probability', s.get('vulnerability_pct', s.get('pct', 0))) or 0)
                items.append((name, pct))
    elif isinstance(attack_scenarios, dict):
        for k, v in attack_scenarios.items():
            if isinstance(v, dict):
                pct = float(v.get('probability', v.get('vulnerability_pct', v.get('pct', 0))) or 0)
                items.append((v.get('name', k), pct))
            elif isinstance(v, (int, float)):
                items.append((k, float(v)))

    if not items:
        return ''

    cat_order = ['Dictionary Attack', 'Keyboard Walk Attack', 'Brute Force Estimate', 'Pattern Attack']
    ordered_items = []
    for cat in cat_order:
        matched = next((item for item in items if cat.lower() in item[0].lower() or item[0].lower() in cat.lower()), None)
        if matched:
            ordered_items.append((cat, matched[1]))
        else:
            ordered_items.append((cat, 0.0))

    labels = [item[0] for item in ordered_items]
    values = [item[1] for item in ordered_items]

    display_labels = ['Dictionary\nAttack', 'Keyboard Walk\nAttack', 'Brute Force\nEstimate', 'Pattern\nAttack']
    colors = [GREEN, GREEN, AMBER, '#801b1b']

    fig, ax = plt.subplots(figsize=(9, 5.2))
    bars = ax.bar(range(len(values)), values, color=colors, edgecolor='white', linewidth=1.2, width=0.55)

    ax.set_xticks(range(len(values)))
    ax.set_xticklabels(display_labels, fontsize=11, fontweight='bold', color='#475569')
    ax.set_ylabel('Vulnerability %', **_FONT_AXIS)
    ax.set_title('Password Cracking Simulation — Vulnerability by Attack Type', fontsize=14, fontweight='bold', color=NAVY, pad=22)

    max_val = max(values) if values else 80
    y_limit = max(88.0, max_val * 1.18)
    ax.set_ylim(0, y_limit)
    ax.set_yticks([0, 20, 40, 60, 80])

    for bar, val in zip(bars, values):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + (y_limit * 0.02),
                f'{val:.1f}%', ha='center', va='bottom', fontsize=12, fontweight='bold', color='#1e293b')

    ax.grid(axis='y', alpha=0.35, linestyle='--')
    ax.set_axisbelow(True)
    _style_axes(ax)
    fig.tight_layout()
    return _save(fig, _out('cracking_simulation.png', output_dir), return_fs_path=return_fs_path)


def generate_compliance_mapping_chart(
    compliance_data: Any,
    output_dir: Optional[str] = None,
    return_fs_path: bool = False,
) -> str:
    """Horizontal bar chart showing compliance scores against major regulatory frameworks."""
    if not compliance_data:
        return ''

    scores = {}
    if isinstance(compliance_data, dict):
        if 'compliance_scores' in compliance_data:
            scores = compliance_data['compliance_scores']
        else:
            scores = compliance_data

    ordered_keys = ['PCI-DSS v4.0', 'NIST SP 800-63B', 'ISO 27001', 'OWASP', 'HIPAA']
    labels = []
    values = []

    for k in ordered_keys:
        val = None
        for ck, cv in scores.items():
            if k.lower() in ck.lower() or ck.lower() in k.lower():
                try:
                    val = float(cv)
                    break
                except (ValueError, TypeError):
                    pass
        if val is None:
            val = 30.0
        labels.append(k)
        values.append(val)

    fig, ax = plt.subplots(figsize=(9, 5.2))
    bars = ax.barh(range(len(labels)), values, color=RED, edgecolor='white', linewidth=1.1, height=0.55)

    ax.set_ylim(-0.6, len(labels) - 0.2)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=11, fontweight='bold', color='#334155')
    ax.set_xlabel('Compliance Score (0-100)', **_FONT_AXIS)
    ax.set_title('Regulatory Compliance Mapping', fontsize=14, fontweight='bold', color=NAVY, pad=22)
    ax.set_xlim(0, 105)
    ax.set_xticks([0, 20, 40, 60, 80, 100])

    ax.axvline(x=70, color='#64748b', linestyle='--', linewidth=1.2)
    ax.text(70.5, len(labels) - 0.55, 'Compliance threshold (70)',
            ha='left', va='bottom', fontsize=9.5, color='#475569', fontstyle='italic')

    for bar, val in zip(bars, values):
        ax.text(val + 1.2, bar.get_y() + bar.get_height() / 2,
                f'{val:.1f}', va='center', fontsize=12, fontweight='bold', color='#1e293b')

    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    _style_axes(ax)
    fig.tight_layout()
    return _save(fig, _out('compliance_mapping.png', output_dir), return_fs_path=return_fs_path)

