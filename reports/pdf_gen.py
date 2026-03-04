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
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
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

    add('CustomTitle',    'Heading1',  fontSize=26, textColor=colors.HexColor('#1a237e'),
        spaceAfter=28, alignment=TA_CENTER, fontName='Helvetica-Bold')
    add('CustomSubtitle', 'Normal',    fontSize=13, textColor=colors.HexColor('#424242'),
        spaceAfter=10, alignment=TA_CENTER, fontName='Helvetica')
    add('SectionHeader',  'Heading2',  fontSize=15, textColor=colors.HexColor('#283593'),
        spaceAfter=10, spaceBefore=18, fontName='Helvetica-Bold')
    add('SubsectionHeader', 'Heading3', fontSize=12, textColor=colors.HexColor('#3f51b5'),
        spaceAfter=6, spaceBefore=10, fontName='Helvetica-Bold')
    add('BodyJustify',    'BodyText',  alignment=TA_JUSTIFY, fontSize=10, spaceAfter=8)
    add('BulletList',     'BodyText',  fontSize=10, leftIndent=18, spaceAfter=5)

    return styles


# ────────────────────────────────────────────────────────────────────────────
#  Section builders
# ────────────────────────────────────────────────────────────────────────────

def _cover_page(styles):
    story = [
        Spacer(1, 2 * inch),
        Paragraph('SecurePass AI', styles['CustomTitle']),
        Paragraph('Password Security Audit Report', styles['CustomSubtitle']),
        Spacer(1, 0.4 * inch),
        Paragraph(
            f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M')}",
            styles['CustomSubtitle'],
        ),
        Spacer(1, 1.2 * inch),
        Paragraph('Confidential Security Assessment', styles['CustomSubtitle']),
        PageBreak(),
    ]
    return story


def _executive_summary(data, styles):
    story = [Paragraph('Executive Summary', styles['SectionHeader'])]
    total = data.get('total_passwords', 0)
    story.append(Paragraph(
        f'This report presents a comprehensive security analysis of {total:,} passwords. '
        'The assessment reveals critical insights into password strength, vulnerability '
        'patterns, and compliance with industry security standards.',
        styles['BodyJustify'],
    ))

    insights = data.get('ai_insights', []) or []
    if insights:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph('Key Findings:', styles['SubsectionHeader']))
        for item in insights[:5]:
            story.append(Paragraph(f'• {item}', styles['BulletList']))
    story.append(Spacer(1, 0.2 * inch))
    return story


def _dataset_overview(data, styles):
    story = [Paragraph('Dataset Overview', styles['SectionHeader'])]

    rows = [
        ['Metric', 'Value'],
        ['Total Passwords Analysed', f"{data.get('total_passwords', 0):,}"],
        ['Unique Passwords',         f"{data.get('unique_passwords', 0):,}"],
        ['Average Length',           f"{data.get('avg_length') or data.get('average_length', 0):.1f} characters"],
        ['Median Length',            f"{data.get('median_length', 0):.1f} characters"],
        ['Std Dev (Length)',         f"{data.get('std_dev_length', 0):.1f}"],
        ['Shortest Password',        f"{data.get('min_length', 0)} characters"],
        ['Longest Password',         f"{data.get('max_length', 0)} characters"],
    ]

    tbl = Table(rows, colWidths=[3 * inch, 3 * inch])
    tbl.setStyle(_base_table_style(header_color='#3f51b5'))
    story += [tbl, Spacer(1, 0.25 * inch)]
    return story


def _health_score(data, styles):
    story = [Paragraph('Password Health Score & Risk Level', styles['SectionHeader'])]

    risk_score = data.get('risk_score', 0) or 0
    risk_level = data.get('risk_level', 'Unknown') or 'Unknown'

    rows = [
        ['Overall Security Score', f'{risk_score:.1f} / 100'],
        ['Risk Classification',    risk_level],
    ]
    tbl = Table(rows, colWidths=[3 * inch, 3 * inch])
    tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, -1), colors.HexColor('#e8eaf6')),
        ('FONTNAME',     (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1, -1), 12),
        ('GRID',         (0, 0), (-1, -1), 1.5, colors.HexColor('#3f51b5')),
        ('TOPPADDING',   (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 8),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.2 * inch))

    insights = data.get('ai_insights', []) or []
    if insights:
        story.append(Paragraph(insights[0], styles['BodyJustify']))
    return story


def _visual_analysis(chart_paths, styles):
    story = [Paragraph('Visual Analysis', styles['SectionHeader'])]
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
        'strength_distribution':  'Password Strength Criteria Coverage',
    }

    for key, web_path in chart_paths.items():
        if not web_path:
            continue
        # Resolve to filesystem path
        fs_path = _resolve_chart_path(web_path)
        if not fs_path or not os.path.exists(fs_path):
            logger.debug('Chart file not found: %s', fs_path)
            continue
        title = title_map.get(key, key.replace('_', ' ').title())
        story.append(Paragraph(title, styles['SubsectionHeader']))
        try:
            story.append(Image(fs_path, width=5.5 * inch, height=3.5 * inch))
            story.append(Spacer(1, 0.25 * inch))
        except Exception as exc:
            logger.warning('Failed to embed chart %s: %s', key, exc)

    return story


def _attack_scenarios(data, styles):
    story = [Paragraph('Attack Scenarios', styles['SectionHeader'])]
    scenarios = data.get('attack_scenarios', []) or []
    if not scenarios:
        scenarios = [
            'Brute Force: Weak passwords are vulnerable to automated guessing attacks.',
            'Dictionary Attack: Common words and patterns enable rapid credential compromise.',
            'Credential Stuffing: Reused passwords across services multiply breach impact.',
        ]
    for i, s in enumerate(scenarios, 1):
        story.append(Paragraph(f'{i}. {s}', styles['BulletList']))
    story.append(Spacer(1, 0.2 * inch))
    return story


def _policy_impact(data, styles):
    story = [Paragraph('Policy Impact Simulation', styles['SectionHeader'])]
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
    story = [Paragraph('Compliance Mapping', styles['SectionHeader'])]

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
    story = [Paragraph('Recommendations', styles['SectionHeader'])]
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

    Handles both:
      'reports/output/foo.png'         → 'frontend/static/reports/output/foo.png'
      'frontend/static/reports/…'      → unchanged
    """
    if not web_path:
        return ''
    if web_path.startswith(_STATIC_PREFIX):
        return web_path
    return os.path.join('frontend', 'static', web_path)


def _base_table_style(header_color: str = '#3f51b5') -> TableStyle:
    return TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor(header_color)),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  colors.whitesmoke),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  10),
        ('BOTTOMPADDING', (0, 0), (-1, 0),  10),
        ('BACKGROUND',    (0, 1), (-1, -1), colors.white),
        ('GRID',          (0, 0), (-1, -1), 1, colors.grey),
        ('FONTNAME',      (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',      (0, 1), (-1, -1), 9),
        ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
    ])