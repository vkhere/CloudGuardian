"""
core/pdfreport.py
=================
Builds the one-click executive PDF export.

WHY REPORTLAB AND NOT A CHART SCREENSHOT
    Rendering Plotly charts to image files needs the kaleido binary, which is
    a large extra dependency and a common source of "works on my machine"
    failures. Everything here is drawn with reportlab primitives instead, so
    the export works offline on any machine that can pip install the package.

The output is a self-contained management summary: posture, severity mix,
top risks, compliance position, detection coverage and review status.
"""

from __future__ import annotations

import io
from datetime import datetime

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

ACCENT = colors.HexColor("#1F4E79")
SEV_COLORS = {
    "Critical": colors.HexColor("#B3261E"),
    "High": colors.HexColor("#E8590C"),
    "Medium": colors.HexColor("#F0A202"),
    "Low": colors.HexColor("#3D8BFD"),
    "Informational": colors.HexColor("#8A8F98"),
}


def _styles() -> dict:
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], fontSize=24,
                                textColor=ACCENT, spaceAfter=6),
        "sub": ParagraphStyle("s", parent=ss["Normal"], fontSize=11,
                              textColor=colors.HexColor("#5A5F66"),
                              alignment=TA_CENTER, spaceAfter=18),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=14,
                             textColor=ACCENT, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=14),
        "small": ParagraphStyle("sm", parent=ss["Normal"], fontSize=8,
                                textColor=colors.HexColor("#5A5F66")),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8, leading=11),
    }


def _table(data, widths, header=True, align_right=None):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3EB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    if align_right:
        for col in align_right:
            style.append(("ALIGN", (col, 1), (col, -1), "RIGHT"))
    t.setStyle(TableStyle(style))
    return t


def _kpi_row(items):
    """A single row of large metric boxes."""
    data = [[Paragraph(f"<font size=16><b>{v}</b></font><br/>"
                       f"<font size=7 color='#5A5F66'>{k}</font>", _styles()["cell"])
             for k, v in items]]
    t = Table(data, colWidths=[(170 * mm) / len(items)] * len(items))
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3EB")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F9FC")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _severity_bar(sev_counts: dict, total: int):
    """A proportional stacked bar drawn as a one-row table."""
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    present = [(s, sev_counts.get(s, 0)) for s in order if sev_counts.get(s, 0)]
    if not present or total == 0:
        return Paragraph("No open findings.", _styles()["body"])
    widths, cells, styles = [], [], [
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
    for i, (sev, n) in enumerate(present):
        widths.append(170 * mm * n / total)
        cells.append(f"{sev} {n}")
        styles.append(("BACKGROUND", (i, 0), (i, 0), SEV_COLORS.get(sev, colors.grey)))
    t = Table([cells], colWidths=widths)
    t.setStyle(TableStyle(styles))
    return t


def build_pdf(
    current: pd.DataFrame,
    fails: pd.DataFrame,
    posture: dict,
    iso_score: float,
    cis_score: float,
    coverage: dict,
    funnel: dict,
    llm: dict,
    view_label: str,
) -> bytes:
    """Render the executive report and return it as PDF bytes."""
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title="CloudGuardian executive summary",
        author="CloudGuardian Console",
    )
    story = []

    story.append(Paragraph("CloudGuardian", st["title"]))
    story.append(Paragraph(
        f"Cloud security posture summary &mdash; {view_label}<br/>"
        f"Generated {datetime.now().strftime('%d %B %Y, %H:%M')}", st["sub"]))

    clouds = ", ".join(sorted(c for c in current["cloud"].unique() if c)) or "-"
    story.append(_kpi_row([
        ("Open findings", posture.get("fails", 0)),
        ("Critical + high", posture.get("crit_high", 0)),
        ("Checks passing", f"{posture.get('pass_rate', 0)}%"),
        ("ISO 27001", f"{iso_score}%"),
        ("CIS", f"{cis_score}%"),
    ]))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(f"<b>Scope.</b> {clouds}. "
                           f"{posture.get('checks', 0)} checks evaluated, "
                           f"{posture.get('fails', 0)} failing.", st["body"]))

    story.append(Paragraph("Severity distribution", st["h1"]))
    sev_counts = fails["severity"].value_counts().to_dict() if not fails.empty else {}
    story.append(_severity_bar(sev_counts, len(fails)))

    story.append(Paragraph("Highest open risks", st["h1"]))
    if fails.empty:
        story.append(Paragraph("No open findings in this view.", st["body"]))
    else:
        top = fails.head(10)
        rows = [["ID", "Cloud", "Service", "Severity", "Risk", "Finding"]]
        for _, r in top.iterrows():
            rows.append([
                Paragraph(str(r["finding_id"]), st["cell"]),
                str(r["cloud"]), str(r["service"]), str(r["severity"]),
                str(int(r["risk_score"])),
                Paragraph(str(r["title"]), st["cell"]),
            ])
        story.append(_table(rows, [28 * mm, 16 * mm, 20 * mm, 18 * mm, 12 * mm, 76 * mm],
                            align_right=[4]))

    story.append(PageBreak())

    story.append(Paragraph("Compliance position", st["h1"]))
    story.append(_table(
        [["Framework", "Controls passing"],
         ["ISO 27001 Annex A", f"{iso_score}%"],
         ["CIS Benchmark", f"{cis_score}%"]],
        [90 * mm, 80 * mm]))

    story.append(Paragraph("Detection coverage", st["h1"]))
    story.append(Paragraph(
        f"{coverage.get('detected', 0)} of {coverage.get('total', 0)} deliberate "
        f"misconfigurations were detected by the scanning pipeline "
        f"({coverage.get('pct', 0)}%). "
        f"{coverage.get('missed', 0)} were not raised by any tool.", st["body"]))

    story.append(Paragraph("Remediation gate", st["h1"]))
    story.append(_table(
        [["Status", "Findings"]] + [[k, str(v)] for k, v in funnel.items()],
        [90 * mm, 80 * mm], align_right=[1]))

    story.append(Paragraph("LLM guidance assurance", st["h1"]))
    story.append(_table(
        [["Verification outcome", "Count"],
         ["Verified against raw scanner data", str(llm.get("verified", 0))],
         ["Needs manual review", str(llm.get("needs_review", 0))],
         ["Flagged as unsupported", str(llm.get("flagged", 0))],
         ["Flagged rate", f"{llm.get('hallucination_rate', 0)}%"]],
        [90 * mm, 80 * mm], align_right=[1]))

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        "Generated by the CloudGuardian Console. Remediation guidance was produced "
        "with LLM assistance and verified against raw scanner output; items marked "
        "flagged were not substantiated by the underlying finding data.", st["small"]))

    doc.build(story)
    return buf.getvalue()
