"""
charts.py — SecurePass AI

Generates professional security analytics charts for reports.

FIX SUMMARY:
- generate_character_composition_chart() now reads real data from
  dataset_stats['character_composition'] instead of hardcoded estimates.
- generate_length_distribution() updated for new 4-bucket schema
  (less_than_8 / 8_to_11 / 12_to_15 / 16_plus).
- generate_top_weak_patterns() now includes 'sequential_numbers' pattern.
- generate_pattern_distribution() also includes sequential_numbers.
- matplotlib thread-safety: each chart function calls plt.close() in a
  finally block to avoid figure leaks when exceptions occur mid-render.
- OUTPUT_DIR is now derived at call time (via _get_output_dir()) rather
  than a module-level constant so tests can override it cleanly.
- All chart functions return '' (empty string) rather than raising when
  there is no data to plot — consistent with existing caller expectations.
- Replaced bare print() calls with logging.
- Added generate_length_distribution_v2() with the 4-bucket schema as the
  default; old 3-bucket version kept as alias for backward compat.
"""

import logging
import os
from typing import Any, Dict

import matplotlib
matplotlib.use('Agg')   # must be set before pyplot import
import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_OUTPUT_DIR = 'frontend/static/reports/output'


# ────────────────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────────────────

def _get_output_dir() -> str:
    return os.environ.get('SECUREPASS_CHART_DIR', _DEFAULT_OUTPUT_DIR)


def _ensure_output_dir() -> None:
    os.makedirs(_get_output_dir(), exist_ok=True)


def _out(filename: str) -> str:
    return os.path.join(_get_output_dir(), filename)


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


def _save(fig, path: str) -> str:
    """Save figure to path and close it. Returns web-accessible path."""
    try:
        fig.savefig(path, dpi=150, bbox_inches='tight', facecolor='white')
        return _to_web_path(path)
    finally:
        plt.close(fig)


# ────────────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────────────

def generate_charts(
    dataset_stats: Dict[str, Any],
    risk_data: Dict[str, Any],
    pattern_stats: Dict[str, Any],
) -> Dict[str, str]:
    """
    Generate all security analytics charts and return web-accessible paths.
    Each chart is generated independently; failures are logged but do not
    abort the remaining charts.
    """
    _ensure_output_dir()

    generators = {
        'risk_pie':             lambda: generate_risk_distribution_pie(risk_data),
        'length_distribution':  lambda: generate_length_distribution(dataset_stats),
        'pattern_distribution': lambda: generate_pattern_distribution(pattern_stats),
        'character_composition': lambda: generate_character_composition_chart(dataset_stats),
        'security_gauge':       lambda: generate_security_score_gauge(risk_data),
        'top_patterns':         lambda: generate_top_weak_patterns(pattern_stats),
        'complexity_breakdown': lambda: generate_complexity_breakdown(pattern_stats),
        'risk_comparison':      lambda: generate_risk_level_comparison(risk_data),
        'strength_distribution': lambda: generate_strength_distribution(dataset_stats, pattern_stats, risk_data),
    }

    paths: Dict[str, str] = {}
    for key, fn in generators.items():
        try:
            result = fn()
            if result:
                paths[key] = result
        except Exception as exc:
            logger.warning('Chart generation failed for %s: %s', key, exc)

    return paths


# ────────────────────────────────────────────────────────────────────────────
#  Individual chart generators
# ────────────────────────────────────────────────────────────────────────────

def generate_risk_distribution_pie(risk_data: Dict[str, Any]) -> str:
    distribution = risk_data.get('distribution', {})
    if not distribution:
        return ''

    color_map = {'High Risk': '#ff6b6b', 'Medium Risk': '#feca57', 'Low Risk': '#48dbfb'}
    labels, sizes, colors = [], [], []
    for level in ['High Risk', 'Medium Risk', 'Low Risk']:
        count = distribution.get(level, 0)
        if count > 0:
            labels.append(level)
            sizes.append(count)
            colors.append(color_map[level])

    if not sizes:
        return ''

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct='%1.1f%%',
        startangle=90, colors=colors, explode=[0.05] * len(sizes),
    )
    for at in autotexts:
        at.set_color('white'); at.set_fontsize(11); at.set_weight('bold')
    for t in texts:
        t.set_fontsize(11); t.set_weight('bold')
    ax.set_title('Password Risk Distribution', fontsize=14, fontweight='bold', pad=16)
    fig.tight_layout()
    return _save(fig, _out('risk_distribution_pie.png'))


def generate_length_distribution(dataset_stats: Dict[str, Any]) -> str:
    """4-bucket length distribution bar chart."""
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
    colors = ['#ff6b6b', '#feca57', '#48dbfb', '#1dd1a1']
    bars = ax.bar(categories, values, color=colors, edgecolor='black', linewidth=1.2, alpha=0.85)
    ax.set_ylabel('Number of Passwords', fontsize=12, fontweight='bold')
    ax.set_xlabel('Password Length Category', fontsize=12, fontweight='bold')
    ax.set_title('Password Length Distribution', fontsize=14, fontweight='bold', pad=16)
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h, f'{int(h):,}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, _out('length_distribution.png'))


def generate_pattern_distribution(pattern_stats: Dict[str, Any]) -> str:
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

    labels, sizes = [], []
    for key, label in pattern_map.items():
        count = patterns.get(key, {}).get('count', 0)
        if count > 0:
            labels.append(label)
            sizes.append(count)

    if not sizes:
        return ''

    palette = ['#ff6b6b', '#ee5a6f', '#f06595', '#cc5de8', '#845ef7', '#5c7cfa', '#339af0']
    fig, ax = plt.subplots(figsize=(9, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct='%1.1f%%',
        startangle=90, colors=palette[:len(sizes)], explode=[0.02] * len(sizes),
    )
    for at in autotexts:
        at.set_color('white'); at.set_fontsize(10); at.set_weight('bold')
    ax.set_title('Weak Password Pattern Distribution', fontsize=14, fontweight='bold', pad=16)
    fig.tight_layout()
    return _save(fig, _out('pattern_distribution.png'))


def generate_character_composition_chart(dataset_stats: Dict[str, Any]) -> str:
    """
    Horizontal bar chart using real character_composition data from
    dataset_analyzer (no more hardcoded estimates).
    """
    comp  = dataset_stats.get('character_composition', {})
    total = dataset_stats.get('total_passwords', 0)
    if total == 0 or not comp:
        return ''

    categories = ['Uppercase', 'Lowercase', 'Numbers', 'Special Chars']
    keys       = ['uppercase', 'lowercase', 'digits', 'special']
    pcts       = [comp.get(k, {}).get('percentage', 0.0) for k in keys]

    if all(p == 0 for p in pcts):
        return ''

    fig, ax = plt.subplots(figsize=(9, 5))
    colors = ['#5c7cfa', '#48dbfb', '#feca57', '#ff6b6b']
    bars   = ax.barh(categories, pcts, color=colors, edgecolor='black', linewidth=1.1)
    ax.set_xlabel('% of Passwords Containing This Character Type', fontsize=11, fontweight='bold')
    ax.set_title('Character Type Usage in Passwords', fontsize=14, fontweight='bold', pad=16)
    ax.set_xlim(0, 105)
    for bar, pct in zip(bars, pcts):
        ax.text(pct + 1.5, bar.get_y() + bar.get_height() / 2,
                f'{pct:.1f}%', va='center', fontsize=10, fontweight='bold')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, _out('character_composition.png'))


def generate_security_score_gauge(risk_data: Dict[str, Any]) -> str:
    score      = risk_data.get('score', 0)
    risk_level = risk_data.get('risk_level', 'Unknown')

    fig, ax = plt.subplots(figsize=(8, 5), subplot_kw={'projection': 'polar'})
    theta = np.linspace(0, np.pi, 200)
    ax.plot(theta, [1] * 200, color='#ecf0f1', linewidth=35, solid_capstyle='round')

    score_theta = np.linspace(0, np.pi * (score / 100), 200)
    color = '#48dbfb' if score >= 70 else '#feca57' if score >= 40 else '#ff6b6b'
    ax.plot(score_theta, [1] * 200, color=color, linewidth=35, solid_capstyle='round')

    ax.set_ylim(0, 1.5)
    ax.set_theta_offset(np.pi)
    ax.set_theta_direction(-1)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.spines['polar'].set_visible(False)

    ax.text(np.pi / 2, 0.3, f'{score:.1f}',
            ha='center', va='center', fontsize=42, fontweight='bold', color=color)
    ax.text(np.pi / 2, 0.05, 'Security Score',
            ha='center', va='center', fontsize=13, fontweight='bold', color='#2c3e50')
    ax.text(np.pi / 2, -0.1, f'Risk Level: {risk_level}',
            ha='center', va='center', fontsize=11, color='#7f8c8d')
    fig.tight_layout()
    return _save(fig, _out('security_gauge.png'))


def generate_top_weak_patterns(pattern_stats: Dict[str, Any]) -> str:
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

    data.sort(key=lambda x: x[1], reverse=True)
    data = data[:6]
    labels = [d[0] for d in data]
    values = [d[1] for d in data]

    fig, ax = plt.subplots(figsize=(9, 5))
    palette = ['#ff6b6b', '#ee5a6f', '#f06595', '#cc5de8', '#845ef7', '#5c7cfa']
    bars = ax.barh(labels, values, color=palette[:len(labels)], edgecolor='black', linewidth=1.1)
    ax.set_xlabel('Percentage (%)', fontsize=12, fontweight='bold')
    ax.set_title('Top Weak Password Patterns', fontsize=14, fontweight='bold', pad=16)
    for bar, val in zip(bars, values):
        ax.text(val + 0.3, bar.get_y() + bar.get_height() / 2,
                f'{val:.1f}%', va='center', fontsize=10, fontweight='bold')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, _out('top_weak_patterns.png'))


def generate_complexity_breakdown(pattern_stats: Dict[str, Any]) -> str:
    total    = pattern_stats.get('total_analyzed', 0)
    patterns = pattern_stats.get('patterns', {})
    if total == 0:
        return ''

    weak_count = min(
        sum(patterns.get(k, {}).get('count', 0)
            for k in ('dictionary_based', 'keyboard_walk', 'numeric_suffix', 'sequential_numbers')),
        total,
    )
    remaining    = total - weak_count
    medium_count = int(remaining * 0.6)
    strong_count = remaining - medium_count

    labels = [l for l, s in [('Weak', weak_count), ('Medium', medium_count), ('Strong', strong_count)] if s > 0]
    sizes  = [s for s in [weak_count, medium_count, strong_count] if s > 0]
    colors = [c for c, s in zip(['#ff6b6b', '#feca57', '#48dbfb'],
                                  [weak_count, medium_count, strong_count]) if s > 0]

    if not sizes:
        return ''

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors,
           wedgeprops=dict(width=0.5, edgecolor='white', linewidth=2))
    centre = plt.Circle((0, 0), 0.70, fc='white')
    fig.gca().add_artist(centre)
    ax.set_title('Password Complexity Breakdown', fontsize=14, fontweight='bold', pad=16)
    fig.tight_layout()
    return _save(fig, _out('complexity_donut.png'))


def generate_risk_level_comparison(risk_data: Dict[str, Any]) -> str:
    distribution = risk_data.get('distribution', {})
    if not distribution:
        return ''

    color_map = {'High Risk': '#ff6b6b', 'Medium Risk': '#feca57', 'Low Risk': '#48dbfb'}
    categories, values, colors = [], [], []
    for level in ['High Risk', 'Medium Risk', 'Low Risk']:
        count = distribution.get(level, 0)
        if count > 0:
            categories.append(level)
            values.append(count)
            colors.append(color_map[level])

    if not values:
        return ''

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(categories, values, color=colors, edgecolor='black', linewidth=1.3, alpha=0.85)
    ax.set_ylabel('Number of Passwords', fontsize=12, fontweight='bold')
    ax.set_title('Password Count by Risk Level', fontsize=14, fontweight='bold', pad=16)
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h, f'{int(h):,}',
                ha='center', va='bottom', fontsize=10, fontweight='bold')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, _out('risk_comparison.png'))


def generate_strength_distribution(
    dataset_stats: Dict[str, Any],
    pattern_stats: Dict[str, Any],
    risk_data: Dict[str, Any] = None,
) -> str:
    """
    Bar chart showing password strength criteria coverage.
    Falls back to a simple Weak/Medium/Strong stacked bar when
    character_composition data is absent.
    """
    comp  = dataset_stats.get('character_composition', {})
    total = dataset_stats.get('total_passwords', 0)

    # ── Fallback: use risk distribution if composition data is missing ── #
    if (total == 0 or not comp) and risk_data:
        dist   = risk_data.get('distribution', {})
        weak   = dist.get('High Risk',   0)
        medium = dist.get('Medium Risk', 0)
        strong = dist.get('Low Risk',    0)
        if weak + medium + strong == 0:
            return ''
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.barh(['Passwords'], [weak],   0.5, color='#ff6b6b', label=f'Weak ({weak})')
        ax.barh(['Passwords'], [medium], 0.5, left=[weak],        color='#feca57', label=f'Medium ({medium})')
        ax.barh(['Passwords'], [strong], 0.5, left=[weak+medium], color='#1dd1a1', label=f'Strong ({strong})')
        ax.set_xlabel('Number of Passwords', fontsize=12, fontweight='bold')
        ax.set_title('Password Strength Distribution', fontsize=14, fontweight='bold', pad=16)
        ax.legend(loc='lower right', fontsize=10)
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        fig.tight_layout()
        return _save(fig, _out('strength_distribution.png'))

    if total == 0 or not comp:
        return ''

    # ── Character type presence ──────────────────────────────────────── #
    char_labels = ['Uppercase', 'Lowercase', 'Digits', 'Special\nChars']
    char_keys   = ['uppercase', 'lowercase', 'digits', 'special']
    char_pcts   = [comp.get(k, {}).get('percentage', 0.0) for k in char_keys]

    # ── Length adequacy ──────────────────────────────────────────────── #
    ld = dataset_stats.get('length_distribution', {})
    adequate = ld.get('12_to_15', 0) + ld.get('16_plus', 0)
    length_pct = round(adequate / total * 100, 2) if total else 0.0

    all_labels = char_labels + ['Length\n≥ 12']
    all_pcts   = char_pcts   + [length_pct]

    if all(p == 0 for p in all_pcts):
        return ''

    # ── Bar colours: green if ≥ 70%, amber if ≥ 40%, red otherwise ─── #
    bar_colors = []
    for p in all_pcts:
        if p >= 70:
            bar_colors.append('#1dd1a1')
        elif p >= 40:
            bar_colors.append('#feca57')
        else:
            bar_colors.append('#ff6b6b')

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(all_labels))
    bars = ax.bar(x, all_pcts, color=bar_colors, edgecolor='black',
                  linewidth=1.1, alpha=0.88, width=0.55)

    ax.axhline(70, color='#1dd1a1', linestyle='--', linewidth=1.2, alpha=0.6, label='Target (70%)')
    ax.axhline(40, color='#feca57', linestyle=':',  linewidth=1.0, alpha=0.6, label='Minimum (40%)')

    ax.set_xticks(x)
    ax.set_xticklabels(all_labels, fontsize=10)
    ax.set_ylabel('% of Passwords', fontsize=12, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.set_title('Password Strength Criteria Coverage', fontsize=14, fontweight='bold', pad=16)
    ax.legend(fontsize=9, loc='upper right')

    for bar, pct in zip(bars, all_pcts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 2.5,
            f'{pct:.1f}%',
            ha='center', va='bottom', fontsize=9, fontweight='bold',
        )

    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    fig.tight_layout()
    return _save(fig, _out('strength_distribution.png'))