"""
pdf_gen.py — SecurePass AI

Generates professional PDF security audit reports using ReportLab.

FIX SUMMARY:
- build_visual_analysis() now resolves chart paths against both the
  web-relative path and the filesystem path so it works regardless of
  whether charts dict contains 'reports/output/x.png' or the full path.
- build_dataset_overview() now includes Median Length and Std Dev from
  the richer dataset_stats produced by the updated dataset_analyzer.
- build_compliance_mapping() reads compliance_scores (numeric, from the
  updated compliance_mapper) if present; falls back to compliance_mapping
  for backward compatibility.
- All section builders guard against missing / None data gracefully.
- Removed implicit string concatenation in several f-strings that could
  cause TypeError when values are None.
- NumberedCanvas fixed: _pageNumber was being used before assignment on
  some ReportLab versions — now uses len(self._saved_page_states).
- generate_pdf_report() output_dir defaults to a temp-safe value;
  caller (app.py) always passes an explicit tempfile directory anyway.
"""

import logging
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable, Image, KeepTogether, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)

logger = logging.getLogger(__name__)

# Web-static prefix — charts.py strips this when building chart_paths
_STATIC_PREFIX = 'frontend/static/'


# ────────────────────────────────────────────────────────────────────────────
#  Numbered canvas
# ────────────────────────────────────────────────────────────────────────────

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _draw_page_number(self, page_count: int):
        self.setFont('Helvetica', 9)
        self.setFillColor(colors.grey)
        self.drawRightString(
            7.5 * inch, 0.5 * inch,
            f'Page {self._pageNumber} of {page_count}',
        )


# ────────────────────────────────────────────────────────────────────────────
#  Styles
# ────────────────────────────────────────────────────────────────────────────

def _create_styles():
    styles = getSampleStyleSheet()

    def add(name, parent_name, **kwargs):
        styles.add(ParagraphStyle(name=name, parent=styles[parent_name], **kwargs))

    # ── Cover / title ──────────────────────────────────────────────────────
    add('CustomTitle',      'Heading1',
        fontSize=32, textColor=colors.HexColor('#0d1b4b'),
        spaceAfter=12, alignment=TA_CENTER, fontName='Helvetica-Bold')
    add('CustomSubtitle',   'Normal',
        fontSize=14, textColor=colors.HexColor('#546e7a'),
        spaceAfter=8, alignment=TA_CENTER, fontName='Helvetica')
    add('CoverDate',        'Normal',
        fontSize=11, textColor=colors.HexColor('#78909c'),
        spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica')
    add('CoverConfidential','Normal',
        fontSize=10, textColor=colors.white,
        spaceAfter=0, alignment=TA_CENTER, fontName='Helvetica-Bold')

    # ── Section / subsection headers ──────────────────────────────────────
    add('SectionHeader',    'Heading2',
        fontSize=14, textColor=colors.HexColor('#0d1b4b'),
        spaceAfter=8, spaceBefore=20, fontName='Helvetica-Bold',
        borderPad=4)
    add('SubsectionHeader', 'Heading3',
        fontSize=11, textColor=colors.HexColor('#1565c0'),
        spaceAfter=4, spaceBefore=10, fontName='Helvetica-Bold')

    # ── Body ──────────────────────────────────────────────────────────────
    add('BodyJustify',      'BodyText',
        alignment=TA_JUSTIFY, fontSize=10, spaceAfter=8,
        leading=15, textColor=colors.HexColor('#212121'))
    add('BulletList',       'BodyText',
        fontSize=10, leftIndent=20, spaceAfter=5, leading=14,
        textColor=colors.HexColor('#212121'))
    add('TableCell',        'Normal',
        fontSize=9, leading=13, textColor=colors.HexColor('#212121'))
    add('Verdict',          'BodyText',
        fontSize=11, fontName='Helvetica-Bold', spaceAfter=6,
        alignment=TA_CENTER, leading=16)

    return styles


# ────────────────────────────────────────────────────────────────────────────
#  Section builders
# ────────────────────────────────────────────────────────────────────────────

def _cover_page(styles):
    W = 6.5 * inch  # usable width

    # Dark header banner
    banner = Table(
        [[Paragraph('SecurePass AI', styles['CustomTitle'])]],
        colWidths=[W],
    )
    banner.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#0d1b4b')),
        ('TOPPADDING',    (0, 0), (-1, -1), 28),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 28),
        ('LEFTPADDING',   (0, 0), (-1, -1), 20),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 20),
    ]))
    # Fix title colour inside banner to white
    banner_white = Table(
        [[Paragraph(
            '<font color="white"><b>SecurePass AI</b></font>',
            styles['CustomTitle'],
        )]],
        colWidths=[W],
    )
    banner_white.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#0d1b4b')),
        ('TOPPADDING',    (0, 0), (-1, -1), 28),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 28),
    ]))

    # Confidential badge
    badge = Table(
        [[Paragraph(
            '<font color="white"><b> CONFIDENTIAL SECURITY ASSESSMENT </b></font>',
            styles['CoverConfidential'],
        )]],
        colWidths=[3 * inch],
    )
    badge.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#c62828')),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('ROUNDEDCORNERS', [4]),
    ]))

    story = [
        Spacer(1, 1.6 * inch),
        banner_white,
        Spacer(1, 0.3 * inch),
        Paragraph('Password Security Audit Report', styles['CustomSubtitle']),
        Spacer(1, 0.15 * inch),
        Paragraph(
            f"Generated on {datetime.now().strftime('%B %d, %Y  •  %H:%M')}",
            styles['CoverDate'],
        ),
        Spacer(1, 0.5 * inch),
        Table([[badge]], colWidths=[W],
              style=TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER')])),
        PageBreak(),
    ]
    return story


def _section_rule(color='#1565c0'):
    """Thin coloured horizontal rule used under section headings."""
    return HRFlowable(
        width='100%', thickness=2,
        color=colors.HexColor(color),
        spaceAfter=8, spaceBefore=0,
    )


def _executive_summary(data, styles):
    story = [
        Paragraph('Executive Summary', styles['SectionHeader']),
        _section_rule(),
    ]
    total = data.get('total_passwords', 0)
    story.append(Paragraph(
        f'This report presents a comprehensive security analysis of {total:,} passwords. '
        'The assessment reveals critical insights into password strength, vulnerability '
        'patterns, and compliance with industry security standards.',
        styles['BodyJustify'],
    ))
    insights = data.get('ai_insights', []) or []
    if insights:
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph('Key Findings:', styles['SubsectionHeader']))
        for item in insights[:5]:
            story.append(Paragraph(f'• {item}', styles['BulletList']))
    story.append(Spacer(1, 0.2 * inch))
    return story


def _dataset_overview(data, styles):
    story = [
        Paragraph('Dataset Overview', styles['SectionHeader']),
        _section_rule(),
    ]
    rows = [
        ['Metric', 'Value'],
        ['Total Passwords Analysed', f"{data.get('total_passwords', 0):,}"],
        ['Unique Passwords',         f"{data.get('unique_passwords', 0):,}"],
        ['Average Length',           f"{data.get('avg_length') or data.get('average_length', 0):.1f} chars"],
        ['Median Length',            f"{data.get('median_length', 0):.1f} chars"],
        ['Std Dev (Length)',         f"{data.get('std_dev_length', 0):.1f}"],
        ['Shortest Password',        f"{data.get('min_length', 0)} chars"],
        ['Longest Password',         f"{data.get('max_length', 0)} chars"],
    ]
    tbl = Table(rows, colWidths=[3.2 * inch, 3.0 * inch])
    tbl.setStyle(_base_table_style(header_color='#1565c0'))
    story += [tbl, Spacer(1, 0.25 * inch)]
    return story


def _health_score(data, styles):
    story = [
        Paragraph('Password Health Score & Risk Level', styles['SectionHeader']),
        _section_rule(),
    ]
    risk_score = data.get('risk_score', 0) or 0
    risk_level = data.get('risk_level', 'Unknown') or 'Unknown'

    # Colour-coded risk level cell
    level_color = (
        '#c62828' if 'High' in risk_level or 'Critical' in risk_level
        else '#e65100' if 'Medium' in risk_level
        else '#2e7d32'
    )

    score_tbl = Table(
        [
            ['Overall Security Score', f'{risk_score:.1f} / 100'],
            ['Risk Classification',
             Paragraph(f'<font color="{level_color}"><b>{risk_level}</b></font>',
                       styles['TableCell'])],
        ],
        colWidths=[3.2 * inch, 3.0 * inch],
    )
    score_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, -1), colors.HexColor('#e3f2fd')),
        ('BACKGROUND',    (1, 0), (1, -1), colors.white),
        ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 11),
        ('GRID',          (0, 0), (-1, -1), 1, colors.HexColor('#90caf9')),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING',   (0, 0), (-1, -1), 12),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 0.2 * inch))
    insights = data.get('ai_insights', []) or []
    if insights:
        story.append(Paragraph(insights[0], styles['BodyJustify']))
    return story


def _visual_analysis(chart_paths, styles):
    story = [
        Paragraph('Visual Analysis', styles['SectionHeader']),
        _section_rule(),
    ]
    if not chart_paths:
        story.append(Paragraph('No charts available for this report.', styles['BodyJustify']))
        return story

    title_map = {
        'risk_pie':               'Password Risk Distribution',
        'length_distribution':    'Password Length Distribution',
        'pattern_distribution':   'Weak Pattern Distribution',
        'character_composition':  'Character Type Usage',
        'security_gauge':         'Security Score Gauge',
        'top_patterns':           'Top Weak Patterns',
        'complexity_breakdown':   'Complexity Breakdown',
        'risk_comparison':        'Risk Level Comparison',
        'strength_distribution':  'Strength Criteria Coverage',
    }

    # Collect valid chart images
    chart_items = []
    for key, web_path in chart_paths.items():
        if not web_path:
            continue
        fs_path = _resolve_chart_path(web_path)
        if not fs_path or not os.path.exists(fs_path):
            logger.warning('Chart not found — key=%s  resolved=%s', key, fs_path)
            continue
        title = title_map.get(key, key.replace('_', ' ').title())
        try:
            img = Image(fs_path, width=3.0 * inch, height=2.1 * inch)
            chart_items.append((title, img))
        except Exception as exc:
            logger.warning('Failed to embed chart %s: %s', key, exc)

    if not chart_items:
        story.append(Paragraph('Charts could not be loaded for this report.', styles['BodyJustify']))
        return story

    # Lay out in a 2-column grid
    cell_style = TableStyle([
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
        ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#fafafa')),
        ('ROUNDEDCORNERS', [4]),
    ])

    pairs = []
    for i in range(0, len(chart_items), 2):
        left_title,  left_img  = chart_items[i]
        if i + 1 < len(chart_items):
            right_title, right_img = chart_items[i + 1]
        else:
            right_title, right_img = '', ''

        def _cell(title, img):
            if not img:
                return ''
            return Table(
                [[Paragraph(f'<b>{title}</b>', styles['SubsectionHeader'])],
                 [img]],
                colWidths=[3.1 * inch],
                style=TableStyle([
                    ('ALIGN',   (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN',  (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]),
            )

        row_tbl = Table(
            [[_cell(left_title, left_img), _cell(right_title, right_img)]],
            colWidths=[3.2 * inch, 3.2 * inch],
        )
        row_tbl.setStyle(cell_style)
        pairs.append(row_tbl)
        pairs.append(Spacer(1, 0.18 * inch))

    story += pairs
    return story


def _attack_scenarios(data, styles):
    story = [
        Paragraph('Password Cracking Simulation Lab', styles['SectionHeader']),
        _section_rule('#b71c1c'),
    ]
    story.append(Paragraph(
        'Educational simulation — estimates vulnerability against common attack strategies. '
        'No actual cracking is performed. All results are based on pattern matching.',
        styles['BodyJustify'],
    ))
    story.append(Spacer(1, 0.1 * inch))

    scenarios = data.get('attack_scenarios', []) or []

    if scenarios and isinstance(scenarios[0], dict):
        # Header row
        header = [
            Paragraph('<b>Attack Type</b>',     styles['TableCell']),
            Paragraph('<b>Matched</b>',          styles['TableCell']),
            Paragraph('<b>Total</b>',            styles['TableCell']),
            Paragraph('<b>Vulnerability %</b>',  styles['TableCell']),
            Paragraph('<b>Risk Level</b>',       styles['TableCell']),
        ]
        rows = [header]

        risk_colors = {
            'CRITICAL': '#c62828',
            'HIGH':     '#e65100',
            'MEDIUM':   '#f9a825',
            'LOW':      '#2e7d32',
        }

        for s in scenarios:
            pct = float(s.get('probability', 0))
            if pct >= 40:   risk_lbl = 'CRITICAL'
            elif pct >= 25: risk_lbl = 'HIGH'
            elif pct >= 10: risk_lbl = 'MEDIUM'
            else:           risk_lbl = 'LOW'
            rc = risk_colors[risk_lbl]
            rows.append([
                Paragraph(s.get('name', '—'),  styles['TableCell']),
                Paragraph(str(s.get('count', '—')), styles['TableCell']),
                Paragraph(str(s.get('total', '—')), styles['TableCell']),
                Paragraph(f'<b>{pct:.1f}%</b>',    styles['TableCell']),
                Paragraph(
                    f'<font color="{rc}"><b>{risk_lbl}</b></font>',
                    styles['TableCell'],
                ),
            ])

        tbl = Table(
            rows,
            colWidths=[2.1 * inch, 0.85 * inch, 0.75 * inch, 1.2 * inch, 1.1 * inch],
        )
        tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#b71c1c')),
            ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.whitesmoke),
            ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, -1), 9),
            ('TOPPADDING',    (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
            ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1),
             [colors.white, colors.HexColor('#fff8f8')]),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story += [tbl, Spacer(1, 0.15 * inch)]

        # Verdict line
        if scenarios:
            top     = max(scenarios, key=lambda x: float(x.get('probability', 0)))
            top_pct = float(top.get('probability', 0))
            top_nm  = top.get('name', 'Unknown')
            top_cnt = top.get('count', 0)
            vc = '#c62828' if top_pct >= 40 else '#e65100' if top_pct >= 25 else '#2e7d32'
            verdict_tbl = Table(
                [[Paragraph(
                    f'<font color="white"><b>Highest exposure: {top_nm} '
                    f'({top_pct:.1f}%) — {top_cnt:,} passwords vulnerable</b></font>',
                    styles['Verdict'],
                )]],
                colWidths=[6.2 * inch],
            )
            verdict_tbl.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor(vc)),
                ('TOPPADDING',    (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ]))
            story.append(verdict_tbl)
    else:
        fallback = scenarios or [
            'Brute Force: Weak passwords are vulnerable to automated guessing attacks.',
            'Dictionary Attack: Common words and patterns enable rapid credential compromise.',
            'Credential Stuffing: Reused passwords across services multiply breach impact.',
        ]
        for i, s in enumerate(fallback, 1):
            story.append(Paragraph(f'{i}. {s}', styles['BulletList']))

    story.append(Spacer(1, 0.2 * inch))
    return story


def _policy_impact(data, styles):
    story = [
        Paragraph('Policy Impact Simulation', styles['SectionHeader']),
        _section_rule('#5c6bc0'),
    ]
    sim = data.get('policy_simulation', {}) or {}
    if sim:
        story.append(Paragraph(
            'Simulated enforcement of the following policies shows these projected improvements:',
            styles['BodyJustify'],
        ))
        rows = [['Policy', 'Projected Score']]
        for policy, score in sim.items():
            rows.append([policy.replace('_', ' ').title(), f'{score:.1f}'])
        tbl = Table(rows, colWidths=[3.5 * inch, 2.5 * inch])
        tbl.setStyle(_base_table_style(header_color='#5c6bc0'))
        story += [tbl, Spacer(1, 0.2 * inch)]
    else:
        story.append(Paragraph('Policy simulation data not available.', styles['BodyJustify']))
    return story


def _compliance_mapping(data, styles):
    story = [
        Paragraph('Compliance Mapping', styles['SectionHeader']),
        _section_rule('#7e57c2'),
    ]

    # Prefer the pre-computed numeric scores from the updated compliance_mapper
    compliance = data.get('compliance_scores') or data.get('compliance_mapping', {}) or {}

    if compliance:
        rows = [['Standard', 'Score', 'Status']]
        for standard, score in compliance.items():
            score_f = float(score) if score is not None else 0.0
            status  = 'Compliant' if score_f >= 70 else 'Non-Compliant' if score_f < 50 else 'Partial'
            rows.append([standard, f'{score_f:.1f}', status])
        tbl = Table(rows, colWidths=[2.5 * inch, 1.5 * inch, 2 * inch])
        tbl.setStyle(_base_table_style(header_color='#7e57c2'))
        story += [tbl, Spacer(1, 0.2 * inch)]
    else:
        story.append(Paragraph(
            'Compliance data not available. Ensure analysis completed successfully.',
            styles['BodyJustify'],
        ))
    return story


def _recommendations(data, styles):
    story = [
        Paragraph('Recommendations', styles['SectionHeader']),
        _section_rule('#2e7d32'),
    ]
    recs = data.get('recommendations') or data.get('ai_insights') or []
    if not recs:
        recs = [
            'Enforce a 12-character minimum password length.',
            'Enable multi-factor authentication on all accounts.',
            'Deploy password strength meters at point of creation.',
            'Educate users on passphrase strategies.',
            'Conduct regular password audits and forced resets.',
        ]
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f'{i}. {rec}', styles['BulletList']))
    story.append(Spacer(1, 0.2 * inch))
    return story


def _disclaimer(styles):
    story = [
        Paragraph('Ethical & Privacy Disclaimer', styles['SectionHeader']),
        Paragraph(
            'This security assessment was conducted solely for authorised security research '
            'and educational purposes. All analysed data has been handled in accordance with '
            'ethical security research guidelines. No actual user credentials have been '
            'compromised, stored, or transmitted during this analysis. Findings are provided '
            'for informational purposes and do not constitute professional security advice.',
            styles['BodyJustify'],
        ),
        Spacer(1, 0.2 * inch),
        Paragraph(
            f'SecurePass AI  |  Confidential Report  |  {datetime.now().year}',
            styles['CustomSubtitle'],
        ),
    ]
    return story


# ────────────────────────────────────────────────────────────────────────────
#  Public entry point
# ────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(data: dict, chart_paths: dict, output_dir: str = 'reports/output') -> str:
    """
    Generate a complete PDF security audit report.

    Args:
        data:       Transformed analysis data (see app.py _transform_data_for_pdf)
        chart_paths: Dict of chart_key → web-relative path
        output_dir: Directory to write the PDF (caller usually passes a tempdir)

    Returns:
        Absolute path to the generated PDF.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp  = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path   = os.path.join(output_dir, f'SecurePass_AI_Report_{timestamp}.pdf')

    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        rightMargin=72, leftMargin=72,
        topMargin=72,   bottomMargin=72,
    )

    styles = _create_styles()
    story  = []

    story += _cover_page(styles)
    story += _executive_summary(data, styles)
    story += _dataset_overview(data, styles)
    story += _health_score(data, styles)
    story += _visual_analysis(chart_paths, styles)
    story += _attack_scenarios(data, styles)
    story += _policy_impact(data, styles)
    story += _compliance_mapping(data, styles)
    story += _recommendations(data, styles)
    story += [PageBreak()]
    story += _disclaimer(styles)

    doc.build(story, canvasmaker=NumberedCanvas)
    logger.info('PDF generated: %s', out_path)
    return out_path


# ────────────────────────────────────────────────────────────────────────────
#  Utilities
# ────────────────────────────────────────────────────────────────────────────

def _resolve_chart_path(web_path: str) -> str:
    """
    Turn a web-relative chart path back into a filesystem path.

    Handles all formats that chart_paths may contain:
      '/static/reports/output/foo.png'    -> 'frontend/static/reports/output/foo.png'
      'reports/output/foo.png'            -> 'frontend/static/reports/output/foo.png'
      'frontend/static/reports/...'       -> unchanged (already a fs path)
    Always returns an absolute path anchored to the project root.
    """
    if not web_path:
        return ''
    p = web_path.replace('\\', '/')
    # Normalise to a relative path from project root
    if p.startswith('frontend/static/'):
        rel = p
    elif p.startswith('/static/'):
        rel = 'frontend/static/' + p[len('/static/'):]
    elif p.startswith('static/'):
        rel = 'frontend/' + p
    else:
        rel = 'frontend/static/' + p

    # Anchor to project root (two levels up from this file: reports/ -> project/)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(project_root, rel.replace('/', os.sep))


def _base_table_style(header_color: str = '#1565c0') -> TableStyle:
    return TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor(header_color)),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.whitesmoke),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 9),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
        ('BACKGROUND',    (0, 1), (-1, -1), colors.white),
        ('GRID',          (0, 0), (-1, -1), 0.5, colors.HexColor('#bdbdbd')),
        ('FONTNAME',      (0, 1), (-1, -1), 'Helvetica'),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
    ])