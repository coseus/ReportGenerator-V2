from __future__ import annotations

import base64
import re
from collections import Counter
from io import BytesIO
from typing import Iterable

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image as RLImage,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from util.charting import risk_trend_png, severity_distribution_png
from util.helpers import normalize_images
from util.i18n import t

SEVERITIES_ORDER = ["Critical", "High", "Moderate", "Low", "Informational"]
SEVERITY_COLORS = {
    "Critical": "#A61B1B",
    "High": "#D35400",
    "Moderate": "#B9770E",
    "Low": "#1F618D",
    "Informational": "#5D6D7E",
}
SEVERITY_SHORT = {
    "Critical": "CRIT",
    "High": "HIGH",
    "Moderate": "MED",
    "Low": "LOW",
    "Informational": "INFO",
}
SECTION_DEFAULTS = {
    "section_1_0_confidentiality_and_legal": (
        "This penetration testing report contains confidential information intended solely for the client organization. "
        "Unauthorized access, distribution, disclosure, or copying of this document or any information contained herein is strictly prohibited. "
        "All findings, methodologies, and artifacts are the intellectual property of the security testing provider unless otherwise stated."
    ),
    "section_1_1_confidentiality_statement": (
        "Findings are provided for informational purposes only and represent the system state at the time of testing only. "
        "The client is solely responsible for implementing and verifying any remediation actions. "
        "The testing team disclaims all liability for any damages resulting from the use of this report or the authorized testing activities."
    ),
    "section_1_2_disclaimer": (
        "This penetration test was conducted exclusively in accordance with the Rules of Engagement and Statement of Work signed by the Client. "
        "No warranties of any kind, express or implied, are provided. The Testing Team and its personnel shall not be held liable for any direct, indirect, incidental, consequential, or punitive damages arising from the use or misuse of this report, its findings, or any actions taken as a result thereof. The report is delivered as is."
    ),
}


def _section_value(report: dict, key: str, default: str = "") -> str:
    value = report.get(key)
    if not value:
        sections = report.get("sections") or {}
        value = sections.get(key)
    if isinstance(value, dict):
        value = value.get("content") or value.get("text") or value.get("value") or ""
    return str(value or default or "").strip()


def _header_label(report: dict) -> str:
    client = str(report.get("client") or "Client").strip()
    project = str(report.get("project") or "").strip()
    return f"{client} · {project}" if project else client


class PentestDocTemplate(BaseDocTemplate):
    def __init__(self, filename, report, report_variant, accent_color, watermark_enabled=False, **kwargs):
        super().__init__(filename, **kwargs)
        self.report = report
        self.report_variant = report_variant
        self.accent_color = accent_color
        self.watermark_enabled = watermark_enabled
        self.heading_log: list[tuple[int, str, int]] = []
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates([
            PageTemplate(id="Cover", frames=[frame], onPage=self._draw_cover_page),
            PageTemplate(id="Body", frames=[frame], onPage=self._draw_body_page),
        ])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and getattr(flowable, "_is_heading", False):
            self.heading_log.append((flowable._heading_level, flowable._heading_text, self.page))

    def _draw_cover_page(self, canvas, doc):
        w, h = A4
        canvas.saveState()
        accent = self.accent_color
        deep = _mix_color(accent, 0.58)
        pale = _mix_color(accent, 0.10)
        canvas.setFillColor(colors.white)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)
        canvas.setFillColor(deep)
        canvas.rect(0, h - 42 * mm, w, 42 * mm, fill=1, stroke=0)
        canvas.setFillColor(pale)
        canvas.rect(0, 0, w, 18 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(_mix_color(accent, 0.35))
        canvas.setLineWidth(1.4)
        canvas.line(18 * mm, 28 * mm, 78 * mm, 28 * mm)
        if self.watermark_enabled:
            _draw_watermark(canvas)
        canvas.restoreState()

    def _draw_body_page(self, canvas, doc):
        w, h = A4
        canvas.saveState()
        accent = self.accent_color
        deep = _mix_color(accent, 0.58)
        if self.watermark_enabled:
            _draw_watermark(canvas)
        canvas.setFillColor(deep)
        canvas.rect(doc.leftMargin, h - 16 * mm, doc.width, 4, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(_mix_color(accent, 0.50))
        canvas.drawString(doc.leftMargin, h - 10 * mm, _header_label(self.report))
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        canvas.drawRightString(w - doc.rightMargin, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()


def _draw_watermark(canvas, text="CONFIDENTIAL"):
    canvas.saveState()
    canvas.setFillGray(0.9, 0.16)
    canvas.setFont("Helvetica-Bold", 58)
    w, h = A4
    canvas.translate(w / 2, h / 2)
    canvas.rotate(35)
    canvas.drawCentredString(0, 0, text)
    canvas.restoreState()


def _hex_to_color(value: str) -> colors.Color:
    try:
        return colors.HexColor(value)
    except Exception:
        return colors.HexColor("#ED863D")


def _mix_color(color: colors.Color, ratio: float) -> colors.Color:
    ratio = max(0.0, min(1.0, ratio))
    return colors.Color(1 - (1 - color.red) * ratio, 1 - (1 - color.green) * ratio, 1 - (1 - color.blue) * ratio)


def _safe_text(text) -> str:
    text = "" if text is None else str(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _risk_rank(value: str) -> int:
    try:
        return SEVERITIES_ORDER.index(value)
    except ValueError:
        return len(SEVERITIES_ORDER)


def _findings_sorted(report: dict) -> list[dict]:
    return sorted(report.get("findings", []) or [], key=lambda f: (_risk_rank(f.get("severity", "Informational")), (f.get("title") or "").lower()))


def _value_list(finding: dict, list_key: str, legacy_key: str):
    vals = finding.get(list_key)
    if not isinstance(vals, list):
        vals = [finding.get(legacy_key)] if finding.get(legacy_key) else []
    return [str(v).strip() for v in vals if str(v).strip()]


def _compute_summary(report: dict) -> dict:
    findings = _findings_sorted(report)
    counts = Counter()
    hosts = Counter()
    evidence_items = 0
    for finding in findings:
        sev = finding.get("severity", "Informational")
        if sev not in SEVERITIES_ORDER:
            sev = "Informational"
        counts[sev] += 1
        host_values = _value_list(finding, "hosts", "host")
        host = host_values[0] if host_values else "Unknown"
        hosts[host] += 1
        evidence_items += len(finding.get("images", []) or []) + (1 if finding.get("code") else 0)
    for item in report.get("detailed_walkthrough", []) or []:
        evidence_items += len(item.get("images", []) or []) + (1 if item.get("code") else 0)
    for item in report.get("additional_reports", []) or []:
        evidence_items += len(item.get("images", []) or []) + (1 if item.get("code") else 0)
    return {
        "findings": findings,
        "counts": {s: counts.get(s, 0) for s in SEVERITIES_ORDER},
        "total": sum(counts.values()),
        "top_host": hosts.most_common(1)[0][0] if hosts else "N/A",
        "highest_severity": next((s for s in SEVERITIES_ORDER if counts[s] > 0), "Informational"),
        "evidence_items": evidence_items,
    }


def _listish(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _meta_values(finding: dict, plural_key: str, singular_key: str):
    vals = _listish(finding.get(plural_key))
    if vals:
        return vals
    return _listish(finding.get(singular_key))


def _image_from_b64(b64_str: str, max_width_mm=150, max_height_mm=120):
    try:
        raw = base64.b64decode(b64_str)
        return _image_from_bytes(raw, max_width_mm=max_width_mm, max_height_mm=max_height_mm)
    except Exception:
        return None


def _image_from_bytes(raw: bytes, max_width_mm=150, max_height_mm=120):
    try:
        img = PILImage.open(BytesIO(raw))
        if img.mode != "RGB":
            img = img.convert("RGB")
        max_w_px = int(max_width_mm * 3.78)
        max_h_px = int(max_height_mm * 3.78)
        ratio = min(max_w_px / img.width, max_h_px / img.height, 1.0)
        new_w = max(1, int(img.width * ratio))
        new_h = max(1, int(img.height * ratio))
        if ratio < 1.0:
            img = img.resize((new_w, new_h), PILImage.LANCZOS)
        bio = BytesIO()
        img.save(bio, format="JPEG", quality=90)
        bio.seek(0)
        out = RLImage(bio, width=(new_w / 3.78) * mm, height=(new_h / 3.78) * mm)
        out.hAlign = "CENTER"
        return out
    except Exception:
        return None


def _build_styles(theme_hex: str):
    accent = _hex_to_color(theme_hex)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverKicker", fontName="Helvetica-Bold", fontSize=11, textColor=colors.white, alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle(name="CoverTitle", fontName="Helvetica-Bold", fontSize=26, leading=30, textColor=colors.HexColor("#111827"), alignment=TA_CENTER, spaceAfter=12))
    styles.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=10, leading=14, textColor=colors.HexColor("#1F2937"), alignment=TA_JUSTIFY, spaceAfter=4))
    styles.add(ParagraphStyle(name="BodySmall", fontName="Helvetica", fontSize=9, leading=12, textColor=colors.HexColor("#4B5563"), spaceAfter=4))
    styles.add(ParagraphStyle(name="Meta", fontName="Helvetica", fontSize=8.4, leading=10.5, textColor=colors.HexColor("#6B7280"), spaceAfter=4))
    styles.add(ParagraphStyle(name="Caption", fontName="Helvetica-Oblique", fontSize=9, leading=11.2, textColor=colors.HexColor("#4B5563"), alignment=TA_CENTER, spaceBefore=4, spaceAfter=10))
    styles.add(ParagraphStyle(name="Heading1Custom", fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=_mix_color(accent, 0.42), spaceBefore=6, spaceAfter=10))
    styles.add(ParagraphStyle(name="Heading2Custom", fontName="Helvetica-Bold", fontSize=12.2, leading=15, textColor=colors.HexColor("#111827"), spaceBefore=5, spaceAfter=6))
    styles.add(ParagraphStyle(name="Badge", fontName="Helvetica-Bold", fontSize=8.5, leading=10, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="CodeBlockCustom", fontName="Courier", fontSize=8.3, leading=10.2, textColor=colors.HexColor("#111827"), backColor=colors.HexColor("#F3F4F6"), borderPadding=6, borderColor=colors.HexColor("#E5E7EB"), borderWidth=0.5, spaceBefore=0, spaceAfter=0))
    styles.add(ParagraphStyle(name="EndingTitle", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=colors.HexColor("#111827"), alignment=TA_CENTER, spaceAfter=10))
    return styles


def _heading(text: str, styles, level: int):
    style = styles["Heading1Custom"] if level == 0 else styles["Heading2Custom"]
    p = Paragraph(text, style)
    p._is_heading = True
    p._heading_level = level
    p._heading_text = text
    return p


def _badge_paragraph(severity: str, styles):
    sev = severity if severity in SEVERITY_COLORS else "Informational"
    return Paragraph(f"<font color='white' backcolor='{SEVERITY_COLORS[sev]}'><b>&nbsp;{SEVERITY_SHORT[sev]}&nbsp;</b></font>", styles["Badge"])


def _draw_logo_story(report, max_w_mm=24):
    img = _image_from_b64(report.get("logo_b64", ""), max_width_mm=max_w_mm, max_height_mm=max_w_mm) if report.get("logo_b64") else None
    return [img, Spacer(1, 8)] if img else []


def _normalize_text(text: str) -> str:
    text = "" if text is None else str(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("•", "\n- ")
    text = re.sub(r"(?<=[:.])\s+n\s+(?=[A-Z0-9])", "\n- ", text)
    text = re.sub(r"\s+n\s+(?=[A-Z0-9][^\n]{0,60}(?:\n|$))", "\n- ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _paragraph_blocks(text: str):
    text = _normalize_text(text)
    if not text:
        return []
    return [block.strip() for block in re.split(r"\n\s*\n", text) if block.strip()]


def _rich_text_flowables(text: str, styles, style_name="Body"):
    flows = []
    for block in _paragraph_blocks(text):
        lines = [ln.strip() for ln in block.split("\n") if ln.strip()]
        bullet_lines = [ln[2:].strip() for ln in lines if ln.startswith("- ")]
        if bullet_lines and len(bullet_lines) == len(lines):
            for item in bullet_lines:
                flows.append(Paragraph(f"• {_safe_text(item)}", styles[style_name]))
        else:
            safe = "<br/>".join(_safe_text(ln) for ln in lines)
            flows.append(Paragraph(safe, styles[style_name]))
    return flows


def _cover_story(report, styles, summary, report_variant):
    story = [Spacer(1, 16 * mm)]
    story += _draw_logo_story(report)
    story.append(Spacer(1, 10 * mm))
    cover_key = f"cover_kicker_{report_variant if report_variant in {'executive','technical'} else 'combined'}"
    story.append(Paragraph(t(report, cover_key), styles["CoverKicker"]))
    story.append(Paragraph(t(report, "report_title"), styles["CoverTitle"]))
    meta_rows = [
        [Paragraph(f"<b>{t(report,'client')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("client", "N/A")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'project')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("project", "N/A")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'assessment_date')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("date", "N/A")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'version')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("version", "1.0")), styles["Body"])],
        [Paragraph(f"<b>{t(report,'lead_tester')}</b>", styles["BodySmall"]), Paragraph(_safe_text(report.get("tester", "N/A")), styles["Body"])],
    ]
    meta = Table(meta_rows, colWidths=[35 * mm, 95 * mm])
    meta.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    story.append(meta)
    story.append(Spacer(1, 12 * mm))
    snapshot = Table([
        [Paragraph("<b>Total Findings</b>", styles["BodySmall"]), Paragraph(str(summary["total"]), styles["Heading2Custom"]), Paragraph("<b>Highest Severity</b>", styles["BodySmall"]), Paragraph(summary["highest_severity"], styles["Heading2Custom"])],
        [Paragraph("<b>Primary Risk Host</b>", styles["BodySmall"]), Paragraph(_safe_text(summary["top_host"]), styles["Body"]), Paragraph("<b>Evidence Items</b>", styles["BodySmall"]), Paragraph(str(summary["evidence_items"]), styles["Body"])],
    ], colWidths=[32 * mm, 38 * mm, 35 * mm, 38 * mm])
    snapshot.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")), ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D1D5DB")), ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(snapshot)
    story.append(Spacer(1, 14))
    story.append(Paragraph(t(report, "confidential_note"), styles["Meta"]))
    story.append(NextPageTemplate("Body"))
    story.append(PageBreak())
    return story


def _initial_toc_entries(variant: str, report: dict):
    base = [
        (0, t(report, "legal"), "—"),
        (1, t(report, "conf_statement"), "—"),
        (1, t(report, "disclaimer"), "—"),
        (1, t(report, "contact_info"), "—"),
        (0, t(report, "exec_overview") if variant in {"executive", "combined"} else t(report, "engagement_overview"), "—"),
        (1, t(report, "assessment_details"), "—"),
        (0, t(report, "findings_summary"), "—"),
    ]
    if report.get("include_charts", True):
        base.append((1, t(report, "risk_charts"), "—"))
    if variant == "executive":
        base += [(0, t(report, "key_findings"), "—"), (0, t(report, "remediation", n="5"), "—")]
    elif variant == "combined":
        base += [(0, t(report, "key_findings"), "—"), (0, t(report, "remediation", n="5"), "—"), (0, t(report, "technical_findings", n="6"), "—"), (0, t(report, "walkthrough", n="7"), "—"), (0, t(report, "additional_reports", n="8"), "—")]
    else:
        base += [(0, t(report, "technical_findings", n="4"), "—"), (0, t(report, "remediation", n="5"), "—"), (0, t(report, "walkthrough", n="6"), "—"), (0, t(report, "additional_reports", n="7"), "—")]
    return base


def _table_of_contents(styles, entries, report):
    rows = []
    for idx, (level, text, page) in enumerate(entries):
        base_style = styles["BodySmall"] if level else styles["Body"]
        toc_style = ParagraphStyle(name=f"TOC_{level}_{idx}", parent=base_style, leftIndent=12 * mm if level else 0, spaceAfter=0)
        rows.append([Paragraph(_safe_text(text), toc_style), Paragraph("........................................", styles["Meta"]), Paragraph(str(page), styles["BodySmall"])])
    tbl = Table(rows, colWidths=[140 * mm, 18 * mm, 10 * mm], repeatRows=0)
    tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (2, 0), (2, -1), "RIGHT"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return [_heading(t(report, "table_of_contents"), styles, 0), Paragraph(t(report, "toc_note"), styles["Meta"]), Spacer(1, 4), tbl, PageBreak()]


def _build_risk_matrix(styles, summary, report):
    pr = {"Critical": t(report, "priority_critical"), "High": t(report, "priority_high"), "Moderate": t(report, "priority_moderate"), "Low": t(report, "priority_low"), "Informational": t(report, "priority_info")}
    rows = [[Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]), Paragraph(f"<b>{t(report,'count')}</b>", styles["BodySmall"]), Paragraph(f"<b>{t(report,'priority')}</b>", styles["BodySmall"])] ]
    for sev in SEVERITIES_ORDER:
        rows.append([Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{sev}</b></font>", styles["Body"]), Paragraph(str(summary["counts"][sev]), styles["Body"]), Paragraph(pr[sev], styles["BodySmall"])])
    tbl = Table(rows, colWidths=[40 * mm, 20 * mm, 75 * mm])
    tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")), ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#E2E8F0")), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("ALIGN", (1, 1), (1, -1), "CENTER")]))
    return tbl


def _charts_section(report, styles, summary):
    if not report.get("include_charts", True):
        return []
    flows = [_heading(t(report, "risk_charts"), styles, 1)]
    sev = _image_from_bytes(severity_distribution_png(summary["counts"]), max_width_mm=155, max_height_mm=85)
    trend = _image_from_bytes(risk_trend_png(summary["findings"]), max_width_mm=155, max_height_mm=85)
    if sev:
        flows += [sev, Spacer(1, 4), Paragraph(t(report, "severity_distribution"), styles["Caption"]), Spacer(1, 8)]
    if trend:
        flows += [trend, Spacer(1, 4), Paragraph(t(report, "risk_trend"), styles["Caption"]), Spacer(1, 8)]
    return flows


def _legal_section(report, styles):
    flows = [_heading(t(report, "legal"), styles, 0)]
    sec_10 = _section_value(report, "section_1_0_confidentiality_and_legal", SECTION_DEFAULTS["section_1_0_confidentiality_and_legal"])
    sec_11 = _section_value(report, "section_1_1_confidentiality_statement", SECTION_DEFAULTS["section_1_1_confidentiality_statement"])
    sec_12 = _section_value(report, "section_1_2_disclaimer", SECTION_DEFAULTS["section_1_2_disclaimer"])
    sec_13 = _section_value(report, "section_1_3_contact_information", "")
    flows += _rich_text_flowables(sec_10, styles)
    flows += [Spacer(1, 6), _heading(t(report, "conf_statement"), styles, 1)]
    flows += _rich_text_flowables(sec_11, styles)
    flows += [Spacer(1, 6), _heading(t(report, "disclaimer"), styles, 1)]
    flows += _rich_text_flowables(sec_12, styles)
    flows += [Spacer(1, 6), _heading(t(report, "contact_info"), styles, 1)]
    if sec_13:
        flows += _rich_text_flowables(sec_13, styles)
        flows.append(Spacer(1, 6))
    contacts = report.get("contacts", []) or []
    if contacts:
        rows = [[Paragraph("<b>Name</b>", styles["BodySmall"]), Paragraph("<b>Title</b>", styles["BodySmall"]), Paragraph("<b>Contact</b>", styles["BodySmall"])] ]
        for c in contacts:
            rows.append([Paragraph(_safe_text(c.get("name", "")), styles["Body"]), Paragraph(_safe_text(c.get("title", "")), styles["Body"]), Paragraph(_safe_text(c.get("contact", "")), styles["Body"])])
        tbl = Table(rows, colWidths=[40 * mm, 58 * mm, 60 * mm])
        tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")), ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")), ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#E5E7EB")), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        flows.extend([tbl, Spacer(1, 6)])
    elif not sec_13:
        flows.append(Paragraph(t(report, "no_contacts"), styles["Body"]))
    flows.append(PageBreak())
    return flows


def _overview_section(report, styles, summary, variant):
    title = t(report, "exec_overview") if variant in {"executive", "combined"} else t(report, "engagement_overview")
    flows = [_heading(title, styles, 0)]
    flows += _rich_text_flowables(report.get("executive_summary") or report.get("assessment_overview") or "No executive summary provided.", styles)
    flows.extend([Spacer(1, 4), _build_risk_matrix(styles, summary, report), Spacer(1, 8), _heading(t(report, "assessment_details"), styles, 1)])
    for label, key in [("Assessment Overview", "assessment_overview"), ("Assessment Details", "assessment_details"), ("Scope", "scope"), ("Scope Exclusions", "scope_exclusions"), ("Client Allowances", "client_allowances")]:
        value = report.get(key, "")
        if value:
            flows.append(Paragraph(f"<b>{_safe_text(label)}</b>", styles["BodySmall"]))
            flows += _rich_text_flowables(value, styles)
    attack_path = report.get("attack_path", []) or []
    if attack_path:
        flows.append(Paragraph(f"<b>{t(report,'attack_path')}</b>", styles["BodySmall"]))
        for item in attack_path:
            flows.append(Paragraph(f"• {_safe_text(item)}", styles["Body"]))
    return flows


def _findings_summary_section(styles, summary, report):
    grouped = {sev: [] for sev in SEVERITIES_ORDER}
    for item in summary["findings"]:
        sev = item.get("severity", "Informational")
        if sev not in grouped:
            sev = "Informational"
        grouped[sev].append(item.get("title") or "Untitled finding")
    rows = [[Paragraph(f"<b>{t(report,'severity')}</b>", styles["BodySmall"]), Paragraph(f"<b>{t(report,'count')}</b>", styles["BodySmall"]), Paragraph("<b>Themes</b>", styles["BodySmall"])] ]
    for sev in SEVERITIES_ORDER:
        rows.append([Paragraph(f"<font color='{SEVERITY_COLORS[sev]}'><b>{sev}</b></font>", styles["Body"]), Paragraph(str(summary["counts"][sev]), styles["Body"]), Paragraph(_safe_text('; '.join(grouped[sev][:2]) or '—'), styles["BodySmall"])])
    tbl = Table(rows, colWidths=[34 * mm, 18 * mm, 83 * mm])
    tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")), ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#E2E8F0")), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("ALIGN", (1, 1), (1, -1), "CENTER")]))
    return [_heading(t(report, "findings_summary"), styles, 0), tbl, Spacer(1, 8)]


def _finding_card(finding: dict, styles, report):
    sev = finding.get("severity", "Informational")
    if sev not in SEVERITY_COLORS:
        sev = "Informational"
    badge_tbl = Table([[_badge_paragraph(sev, styles), Paragraph(f"<b>{_safe_text(sev)} severity</b>", styles["BodySmall"])]], colWidths=[18 * mm, 46 * mm])
    badge_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")), ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#E5E7EB")), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    content = [badge_tbl, Spacer(1, 4)]

    meta = []
    hosts = _meta_values(finding, "hosts", "host")
    ports = _meta_values(finding, "ports", "port")
    cves = _meta_values(finding, "cves", "cve")
    cwes = _meta_values(finding, "cwes", "cwe")
    if hosts:
        meta.append(f"<b>Hosts:</b> {_safe_text(', '.join(hosts))}")
    if ports:
        meta.append(f"<b>Ports:</b> {_safe_text(', '.join(ports))}")
    if cves:
        meta.append(f"<b>CVEs:</b> {_safe_text(', '.join(cves))}")
    if cwes:
        meta.append(f"<b>CWEs:</b> {_safe_text(', '.join(cwes))}")
    for label, key in [("Protocol", "protocol"), ("CVSS", "cvss")]:
        if finding.get(key):
            meta.append(f"<b>{label}:</b> {_safe_text(finding.get(key))}")
    if meta:
        content.append(Paragraph(" | ".join(meta), styles["Meta"]))

    for label_key, key in [("description", "description"), ("likelihood", "likelihood"), ("impact", "impact"), ("tools_used", "tools_used"), ("recommendation", "recommendation"), ("references", "references")]:
        if finding.get(key):
            content.append(Paragraph(f"<b>{t(report, label_key)}</b>", styles["BodySmall"]))
            content.extend(_rich_text_flowables(finding.get(key), styles))

    if finding.get("code"):
        code_lines = _normalize_text(finding.get("code")).split("\n")
        content.append(Paragraph(f"<b>{t(report, 'evidence_output')}</b>", styles["BodySmall"]))
        content.append(Spacer(1, 8))
        content.append(Paragraph("<br/>".join(_safe_text(line) for line in code_lines), styles["CodeBlockCustom"]))
        content.append(Spacer(1, 14))

    for image_item in normalize_images(finding.get("images"), default_prefix=finding.get("title") or "Finding"):
        img = _image_from_b64(image_item["data"])
        if img:
            content.append(img)
            if image_item.get("name"):
                content.append(Spacer(1, 7))
                content.append(Paragraph(_safe_text(image_item["name"]), styles["Caption"]))
            content.append(Spacer(1, 12))

    content.append(Spacer(1, 14))
    return content


def _key_findings_section(styles, summary, report):
    flows = [_heading(t(report, "key_findings"), styles, 0)]
    for idx, finding in enumerate(summary["findings"][: min(6, len(summary["findings"]))], start=1):
        flows.append(_heading(f"4.{idx} {finding.get('title') or 'Untitled finding'}", styles, 1))
        flows.extend(_finding_card(finding, styles, report))
    return flows


def _technical_findings_section(styles, summary, report, section_number="4"):
    flows = [_heading(t(report, "technical_findings", n=section_number), styles, 0)]
    for idx, finding in enumerate(summary["findings"], start=1):
        flows.append(_heading(f"{section_number}.{idx} {finding.get('title') or 'Untitled finding'}", styles, 1))
        flows.extend(_finding_card(finding, styles, report))
    return flows


def _bullet_list(items, styles, report):
    return [Paragraph(f"• {_safe_text(item)}", styles["Body"]) for item in items] if items else [Paragraph(t(report, "no_items"), styles["Body"])]


def _remediation_section(report, styles, section_prefix="5"):
    flows = [_heading(t(report, "remediation", n=section_prefix), styles, 0)]
    for head, items in [(t(report, "short_term", n=section_prefix), report.get("remediation_short", [])), (t(report, "medium_term", n=section_prefix), report.get("remediation_medium", [])), (t(report, "long_term", n=section_prefix), report.get("remediation_long", []))]:
        flows.append(_heading(head, styles, 1))
        flows += _bullet_list(items, styles, report)
        flows.append(Spacer(1, 4))
    return flows


def _walkthrough_section(report, styles, section_prefix="6"):
    steps = report.get("detailed_walkthrough", []) or []
    if not steps:
        return []
    flows = [_heading(t(report, "walkthrough", n=section_prefix), styles, 0)]
    for idx, step in enumerate(steps, start=1):
        title = step.get("name") or step.get("title") or f"Step {idx}"
        flows.append(_heading(f"{section_prefix}.{idx} {title}", styles, 1))
        if step.get("description"):
            flows += [Paragraph(f"<b>{t(report,'description')}</b>", styles["BodySmall"])]
            flows.extend(_rich_text_flowables(step.get("description"), styles))
        if step.get("code"):
            flows += [Paragraph(f"<b>{t(report,'command_output')}</b>", styles["BodySmall"]), Spacer(1, 8), Paragraph("<br/>".join(_safe_text(line) for line in _normalize_text(step.get("code")).split("\n")), styles["CodeBlockCustom"]), Spacer(1, 14)]
        for image_item in normalize_images(step.get("images"), default_prefix=title):
            img = _image_from_b64(image_item["data"])
            if img:
                flows.append(img)
                if image_item.get("name"):
                    flows += [Spacer(1, 7), Paragraph(_safe_text(image_item["name"]), styles["Caption"])]
                flows.append(Spacer(1, 12))
        flows.append(Spacer(1, 10))
    return flows


def _additional_reports_section(report, styles, section_prefix="7"):
    extras = report.get("additional_reports", []) or []
    if not extras:
        return []
    flows = [_heading(t(report, "additional_reports", n=section_prefix), styles, 0)]
    for idx, extra in enumerate(extras, start=1):
        title = extra.get("name") or extra.get("title") or f"Additional Report {idx}"
        flows.append(_heading(f"{section_prefix}.{idx} {title}", styles, 1))
        if extra.get("description"):
            flows.extend(_rich_text_flowables(extra.get("description"), styles))
        if extra.get("code"):
            flows += [Paragraph(f"<b>{t(report,'output')}</b>", styles["BodySmall"]), Spacer(1, 8), Paragraph("<br/>".join(_safe_text(line) for line in _normalize_text(extra.get("code")).split("\n")), styles["CodeBlockCustom"]), Spacer(1, 14)]
        for image_item in normalize_images(extra.get("images"), default_prefix=title):
            img = _image_from_b64(image_item["data"])
            if img:
                flows.append(img)
                if image_item.get("name"):
                    flows += [Spacer(1, 7), Paragraph(_safe_text(image_item["name"]), styles["Caption"])]
                flows.append(Spacer(1, 12))
        flows.append(Spacer(1, 10))
    return flows


def _closing_page(report, styles):
    center_meta = ParagraphStyle(name="EndingMetaCenter", parent=styles["Meta"], alignment=TA_CENTER)
    center_body = ParagraphStyle(name="EndingBodyCenter", parent=styles["BodySmall"], alignment=TA_CENTER)
    story = [PageBreak(), Spacer(1, 78 * mm)]
    if report.get("logo_b64"):
        img = _image_from_b64(report.get("logo_b64"), max_width_mm=30, max_height_mm=30)
        if img:
            story += [img, Spacer(1, 8)]
    story.append(Paragraph(t(report, "end_of_report"), styles["EndingTitle"]))
    story.append(Paragraph(t(report, "last_page"), center_meta))
    story.append(Paragraph(t(report, "closing_text"), center_body))
    return story


def _story(report: dict, variant: str, toc_entries):
    summary = _compute_summary(report)
    styles = _build_styles(report.get("theme_hex", "#ED863D"))
    story = []
    story += _cover_story(report, styles, summary, variant)
    story += _table_of_contents(styles, toc_entries, report)
    story += _legal_section(report, styles)
    story += _overview_section(report, styles, summary, variant)
    story += _findings_summary_section(styles, summary, report)
    story += _charts_section(report, styles, summary)
    if variant == "technical":
        story += _technical_findings_section(styles, summary, report, section_number="4")
        story += _remediation_section(report, styles, section_prefix="5")
        story += _walkthrough_section(report, styles, section_prefix="6")
        story += _additional_reports_section(report, styles, section_prefix="7")
    elif variant == "combined":
        story += _key_findings_section(styles, summary, report)
        story += _remediation_section(report, styles, section_prefix="5")
        story += _technical_findings_section(styles, summary, report, section_number="6")
        story += _walkthrough_section(report, styles, section_prefix="7")
        story += _additional_reports_section(report, styles, section_prefix="8")
    else:
        story += _key_findings_section(styles, summary, report)
        story += _remediation_section(report, styles, section_prefix="5")
    story += _closing_page(report, styles)
    return story


def _build_pdf(report: dict, variant: str, toc_entries):
    buffer = BytesIO()
    accent = _hex_to_color(report.get("theme_hex", "#ED863D"))
    doc = PentestDocTemplate(buffer, report=report, report_variant=variant, accent_color=accent, watermark_enabled=bool(report.get("watermark_enabled", False)), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=22 * mm, bottomMargin=16 * mm, title=f"{report.get('client','Client')} {variant.title()} Pentest Report", author=report.get("tester", "ChatGPT"))
    doc.build(_story(report, variant, toc_entries))
    return buffer.getvalue(), doc.heading_log


def _heading_entries_from_log(log):
    return [(level, text, page) for level, text, page in log if text != t("en", "table_of_contents") and text != t("ro", "table_of_contents")]


def generate_pdf_bytes(report: dict, report_variant: str = "technical") -> bytes:
    variant = (report_variant or "technical").lower()
    if variant not in {"technical", "executive", "combined"}:
        variant = "technical"
    current = _initial_toc_entries(variant, report)
    final_pdf = b""
    for _ in range(4):
        final_pdf, heading_log = _build_pdf(report, variant, current)
        updated = _heading_entries_from_log(heading_log)
        if updated == current:
            break
        current = updated
    final_pdf, _ = _build_pdf(report, variant, current)
    return final_pdf
