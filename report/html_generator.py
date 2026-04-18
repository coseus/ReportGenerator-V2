from __future__ import annotations

from collections import Counter

from jinja2 import Template

from util.charting import png_bytes_to_b64, risk_trend_png, severity_distribution_png
from util.helpers import normalize_images
from util.i18n import get_language, t

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <style>
    body{
      font-family: Arial, sans-serif;
      margin: 30px;
      color: #1f2937;
      line-height: 1.55;
    }
    h1,h2,h3,h4{
      color:#111827;
      margin-top: 24px;
      margin-bottom: 12px;
    }
    .meta{
      color:#6b7280;
      margin-bottom: 18px;
    }
    .card{
      border:1px solid #d1d5db;
      border-radius:8px;
      padding:14px;
      margin:14px 0;
      background:#fff;
    }
    .badge{
      display:inline-block;
      padding:4px 8px;
      border-radius:999px;
      color:white;
      font-weight:bold;
      font-size:12px;
      margin-bottom: 10px;
    }
    .imgcap{
      text-align:center;
      color:#4b5563;
      font-style:italic;
      margin-top:8px;
      margin-bottom:16px;
    }
    img{
      max-width:100%;
      height:auto;
      border:1px solid #e5e7eb;
      border-radius:6px;
      display:block;
      margin-top:10px;
      margin-bottom:0;
    }
    .grid{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:18px;
    }
    .toc{
      padding-left: 22px;
    }
    .toc li{
      margin:4px 0;
    }
    .section-text{
      white-space: pre-wrap;
    }
    .label{
      font-weight:bold;
    }
    .block-title{
      font-weight:bold;
      margin-top:12px;
      margin-bottom:6px;
    }
    .code{
      white-space: pre-wrap;
      background:#f3f4f6;
      border:1px solid #e5e7eb;
      border-radius:6px;
      padding:10px;
      font-family: Consolas, monospace;
      font-size: 12px;
      margin-top:8px;
      margin-bottom:16px;
    }
    .kv{
      margin:4px 0;
    }
    .list{
      margin: 8px 0 12px 20px;
    }
  </style>
</head>
<body>
  <h1>{{ report_title }}</h1>
  <p class="meta">{{ client }} · {{ project }}</p>

  <div class="card">
    <div><span class="label">{{ t_client }}:</span> {{ client }}</div>
    <div><span class="label">{{ t_project }}:</span> {{ project }}</div>
    <div><span class="label">{{ t_date }}:</span> {{ date }}</div>
    <div><span class="label">{{ t_version }}:</span> {{ version }}</div>
    <div><span class="label">{{ t_tester }}:</span> {{ tester }}</div>
  </div>

  <h2>{{ toc }}</h2>
  <ol class="toc">
    {% for item in toc_items %}
      <li>{{ item }}</li>
    {% endfor %}
  </ol>

  <h2>{{ legal_title }}</h2>
  <div class="card section-text">{{ legal_text }}</div>

  <h3>{{ conf_statement_title }}</h3>
  <div class="card section-text">{{ conf_statement_text }}</div>

  <h3>{{ disclaimer_title }}</h3>
  <div class="card section-text">{{ disclaimer_text }}</div>

  <h3>{{ contact_info_title }}</h3>
  {% if contact_info_text %}
    <div class="card section-text">{{ contact_info_text }}</div>
  {% endif %}
  {% if contacts %}
    <div class="card">
      {% for c in contacts %}
        <div class="kv">
          <span class="label">{{ c.name }}</span>
          {% if c.title %} | {{ c.title }}{% endif %}
          {% if c.contact %} | {{ c.contact }}{% endif %}
        </div>
      {% endfor %}
    </div>
  {% else %}
    <div class="card">{{ no_contacts }}</div>
  {% endif %}

  <h2>{{ overview_title }}</h2>
  <div class="card section-text">{{ executive_summary }}</div>

  <h3>{{ assessment_details_title }}</h3>
  <div class="card">
    {% if assessment_overview %}
      <div class="block-title">Assessment Overview</div>
      <div class="section-text">{{ assessment_overview }}</div>
    {% endif %}
    {% if assessment_details %}
      <div class="block-title">Assessment Details</div>
      <div class="section-text">{{ assessment_details }}</div>
    {% endif %}
    {% if scope %}
      <div class="block-title">Scope</div>
      <div class="section-text">{{ scope }}</div>
    {% endif %}
    {% if scope_exclusions %}
      <div class="block-title">Scope Exclusions</div>
      <div class="section-text">{{ scope_exclusions }}</div>
    {% endif %}
    {% if client_allowances %}
      <div class="block-title">Client Allowances</div>
      <div class="section-text">{{ client_allowances }}</div>
    {% endif %}
    {% if attack_path %}
      <div class="block-title">{{ attack_path_title }}</div>
      <ul class="list">
        {% for item in attack_path %}
          <li>{{ item }}</li>
        {% endfor %}
      </ul>
    {% endif %}
  </div>

  <h2>{{ findings_summary }}</h2>
  <div class="card">
    {% for row in severity_rows %}
      <div class="kv"><span class="label">{{ row.severity }}:</span> {{ row.count }}</div>
    {% endfor %}
  </div>

  {% if include_charts %}
    <h3>{{ risk_charts }}</h3>
    <div class="grid">
      <div class="card">
        <img src="data:image/png;base64,{{ severity_chart }}">
        <div class="imgcap">{{ severity_distribution }}</div>
      </div>
      <div class="card">
        <img src="data:image/png;base64,{{ trend_chart }}">
        <div class="imgcap">{{ risk_trend }}</div>
      </div>
    </div>
  {% endif %}

  {% if technical_findings %}
    <h2>{{ technical_findings_title }}</h2>
    {% for finding in technical_findings %}
      <div class="card">
        <h3>{{ finding.number }} {{ finding.title }}</h3>
        <span class="badge" style="background:{{ finding.color }}">{{ finding.severity }}</span>

        {% if finding.meta_lines %}
          {% for line in finding.meta_lines %}
            <div class="kv">{{ line }}</div>
          {% endfor %}
        {% endif %}

        {% if finding.description %}
          <div class="block-title">{{ desc }}</div>
          <div class="section-text">{{ finding.description }}</div>
        {% endif %}

        {% if finding.likelihood %}
          <div class="block-title">{{ likelihood }}</div>
          <div class="section-text">{{ finding.likelihood }}</div>
        {% endif %}

        {% if finding.impact %}
          <div class="block-title">{{ impact }}</div>
          <div class="section-text">{{ finding.impact }}</div>
        {% endif %}

        {% if finding.tools_used %}
          <div class="block-title">{{ tools_used }}</div>
          <div class="section-text">{{ finding.tools_used }}</div>
        {% endif %}

        {% if finding.recommendation %}
          <div class="block-title">{{ recommendation }}</div>
          <div class="section-text">{{ finding.recommendation }}</div>
        {% endif %}

        {% if finding.references %}
          <div class="block-title">{{ references }}</div>
          <div class="section-text">{{ finding.references }}</div>
        {% endif %}

        {% if finding.code %}
          <div class="block-title">{{ evidence_output }}</div>
          <div class="code">{{ finding.code }}</div>
        {% endif %}

        {% for img in finding.images %}
          <img src="data:image/png;base64,{{ img.data }}">
          {% if img.name %}
            <div class="imgcap">{{ img.name }}</div>
          {% endif %}
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}

  {% if walkthrough %}
    <h2>{{ walkthrough_title }}</h2>
    {% for step in walkthrough %}
      <div class="card">
        <h3>{{ step.number }} {{ step.title }}</h3>

        {% if step.description %}
          <div class="block-title">{{ desc }}</div>
          <div class="section-text">{{ step.description }}</div>
        {% endif %}

        {% if step.code %}
          <div class="block-title">{{ command_output }}</div>
          <div class="code">{{ step.code }}</div>
        {% endif %}

        {% for img in step.images %}
          <img src="data:image/png;base64,{{ img.data }}">
          {% if img.name %}
            <div class="imgcap">{{ img.name }}</div>
          {% endif %}
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}

  {% if additional_reports %}
    <h2>{{ additional_reports_title }}</h2>
    {% for extra in additional_reports %}
      <div class="card">
        <h3>{{ extra.number }} {{ extra.title }}</h3>

        {% if extra.description %}
          <div class="section-text">{{ extra.description }}</div>
        {% endif %}

        {% if extra.code %}
          <div class="block-title">{{ output }}</div>
          <div class="code">{{ extra.code }}</div>
        {% endif %}

        {% for img in extra.images %}
          <img src="data:image/png;base64,{{ img.data }}">
          {% if img.name %}
            <div class="imgcap">{{ img.name }}</div>
          {% endif %}
        {% endfor %}
      </div>
    {% endfor %}
  {% endif %}
</body>
</html>
"""

SEV_COLORS = {
    "Critical": "#A61B1B",
    "High": "#D35400",
    "Moderate": "#B9770E",
    "Low": "#1F618D",
    "Informational": "#5D6D7E",
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


def _join_multi(finding: dict, plural_key: str, singular_key: str) -> str:
    values = finding.get(plural_key)
    if isinstance(values, list) and values:
        cleaned = [str(v).strip() for v in values if str(v).strip()]
        if cleaned:
            return ", ".join(cleaned)

    value = str(finding.get(singular_key) or "").strip()
    return value


def _build_finding_meta_lines(finding: dict) -> list[str]:
    lines = []

    hosts = _join_multi(finding, "hosts", "host")
    ports = _join_multi(finding, "ports", "port")
    cves = _join_multi(finding, "cves", "cve")
    cwes = _join_multi(finding, "cwes", "cwe")
    protocol = str(finding.get("protocol") or "").strip()
    cvss = str(finding.get("cvss") or "").strip()

    if hosts:
        lines.append(f"Hosts: {hosts}")
    if ports:
        lines.append(f"Ports: {ports}")
    if cves:
        lines.append(f"CVEs: {cves}")
    if cwes:
        lines.append(f"CWEs: {cwes}")
    if protocol:
        lines.append(f"Protocol: {protocol}")
    if cvss:
        lines.append(f"CVSS: {cvss}")

    return lines


def generate_html_bytes(report: dict, report_variant: str = "technical") -> bytes:
    lang = get_language(report)
    findings = list(report.get("findings") or [])
    counts = Counter((f.get("severity") or "Informational") for f in findings)

    include_charts = bool(report.get("include_charts", True))
    sev_chart = png_bytes_to_b64(severity_distribution_png(counts)) if include_charts else ""
    trend_chart = png_bytes_to_b64(risk_trend_png(findings)) if include_charts else ""

    toc_items = [
        t(lang, "legal"),
        t(lang, "conf_statement"),
        t(lang, "disclaimer"),
        t(lang, "contact_info"),
        t(lang, "exec_overview") if report_variant in {"executive", "combined"} else t(lang, "engagement_overview"),
        t(lang, "assessment_details"),
        t(lang, "findings_summary"),
    ]

    if include_charts:
        toc_items.append(t(lang, "risk_charts"))

    if report_variant == "executive":
        toc_items.extend([
            t(lang, "key_findings"),
            t(lang, "remediation", n="5"),
        ])
    elif report_variant == "combined":
        toc_items.extend([
            t(lang, "technical_findings", n="6"),
            t(lang, "walkthrough", n="7"),
            t(lang, "additional_reports", n="8"),
        ])
    else:
        toc_items.extend([
            t(lang, "technical_findings", n="4"),
            t(lang, "walkthrough", n="6"),
            t(lang, "additional_reports", n="7"),
        ])

    technical_section_number = "6" if report_variant == "combined" else "4"
    walkthrough_section_number = "7" if report_variant == "combined" else "6"
    additional_section_number = "8" if report_variant == "combined" else "7"

    technical_findings = [
        {
            **f,
            "number": f"{technical_section_number}.{idx}",
            "color": SEV_COLORS.get(f.get("severity"), "#5D6D7E"),
            "meta_lines": _build_finding_meta_lines(f),
            "images": normalize_images(f.get("images"), default_prefix=f.get("title") or f"Finding {idx}"),
        }
        for idx, f in enumerate(findings, start=1)
    ]

    walkthrough = [
        {
            **step,
            "number": f"{walkthrough_section_number}.{idx}",
            "title": step.get("name") or step.get("title") or f"Step {idx}",
            "images": normalize_images(step.get("images"), default_prefix=step.get("name") or step.get("title") or f"Step {idx}"),
        }
        for idx, step in enumerate(report.get("detailed_walkthrough") or [], start=1)
    ]

    additional_reports = [
        {
            **extra,
            "number": f"{additional_section_number}.{idx}",
            "title": extra.get("name") or extra.get("title") or f"Additional Report {idx}",
            "images": normalize_images(extra.get("images"), default_prefix=extra.get("name") or extra.get("title") or f"Additional Report {idx}"),
        }
        for idx, extra in enumerate(report.get("additional_reports") or [], start=1)
    ]

    severity_rows = [
        {"severity": sev, "count": counts.get(sev, 0)}
        for sev in ["Critical", "High", "Moderate", "Low", "Informational"]
    ]

    template = Template(HTML_TEMPLATE)
    html = template.render(
        title=f"{report.get('client', 'Client')} {t(lang, 'generated_html')}",
        report_title=t(lang, "report_title"),
        client=report.get("client", "N/A"),
        project=report.get("project", "N/A"),
        date=report.get("date", "N/A"),
        version=report.get("version", "1.0"),
        tester=report.get("tester", "N/A"),
        t_client=t(lang, "client"),
        t_project=t(lang, "project"),
        t_date=t(lang, "assessment_date"),
        t_version=t(lang, "version"),
        t_tester=t(lang, "lead_tester"),
        toc=t(lang, "table_of_contents"),
        toc_items=toc_items,
        legal_title=t(lang, "legal"),
        legal_text=_section_value(
            report,
            "section_1_0_confidentiality_and_legal",
            SECTION_DEFAULTS["section_1_0_confidentiality_and_legal"],
        ),
        conf_statement_title=t(lang, "conf_statement"),
        conf_statement_text=_section_value(
            report,
            "section_1_1_confidentiality_statement",
            SECTION_DEFAULTS["section_1_1_confidentiality_statement"],
        ),
        disclaimer_title=t(lang, "disclaimer"),
        disclaimer_text=_section_value(
            report,
            "section_1_2_disclaimer",
            SECTION_DEFAULTS["section_1_2_disclaimer"],
        ),
        contact_info_title=t(lang, "contact_info"),
        contact_info_text=_section_value(report, "section_1_3_contact_information", ""),
        contacts=report.get("contacts") or [],
        no_contacts=t(lang, "no_contacts"),
        overview_title=t(lang, "exec_overview") if report_variant in {"executive", "combined"} else t(lang, "engagement_overview"),
        executive_summary=report.get("executive_summary") or report.get("assessment_overview") or "No executive summary provided.",
        assessment_details_title=t(lang, "assessment_details"),
        assessment_overview=report.get("assessment_overview", ""),
        assessment_details=report.get("assessment_details", ""),
        scope=report.get("scope", ""),
        scope_exclusions=report.get("scope_exclusions", ""),
        client_allowances=report.get("client_allowances", ""),
        attack_path=report.get("attack_path") or [],
        attack_path_title=t(lang, "attack_path"),
        findings_summary=t(lang, "findings_summary"),
        severity_rows=severity_rows,
        include_charts=include_charts,
        risk_charts=t(lang, "risk_charts"),
        severity_chart=sev_chart,
        trend_chart=trend_chart,
        severity_distribution=t(lang, "severity_distribution"),
        risk_trend=t(lang, "risk_trend"),
        technical_findings_title=t(lang, "technical_findings", n=technical_section_number),
        technical_findings=technical_findings,
        walkthrough_title=t(lang, "walkthrough", n=walkthrough_section_number),
        walkthrough=walkthrough,
        additional_reports_title=t(lang, "additional_reports", n=additional_section_number),
        additional_reports=additional_reports,
        desc=t(lang, "description"),
        likelihood=t(lang, "likelihood"),
        impact=t(lang, "impact"),
        tools_used=t(lang, "tools_used"),
        recommendation=t(lang, "recommendation"),
        references=t(lang, "references"),
        evidence_output=t(lang, "evidence_output"),
        command_output=t(lang, "command_output"),
        output=t(lang, "output"),
    )

    return html.encode("utf-8")