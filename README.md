# Pentest Report Generator

**Modern, bilingual, NIS-oriented penetration-test & vulnerability-assessment reporting.**
A Streamlit application that turns scan output and manual findings into professional, consistent reports in **PDF, DOCX and HTML** — in **English or Romanian**, from a single data model.

---

## Overview

Pentest Report Generator is a self-contained reporting tool for offensive-security and NIS/DORA-style vulnerability-assessment engagements. You import scanner output (or add findings by hand), enrich them in a tabbed web UI, map them to compliance controls, and export a clean, corporate-style report in three formats at once.

Boilerplate sections (legal notices, methodology, attack-chain framing) live in dedicated, editable Python files and are included automatically, so every report is consistent. Engagement-specific data (client, scope, findings, status) is entered in the web UI and saved to JSON on export.

- **Front-end:** Streamlit
- **PDF engine:** ReportLab (DejaVu fonts, full diacritics support)
- **DOCX engine:** python-docx
- **HTML engine:** Jinja2
- **Charts:** Matplotlib

---

## Features

### Reporting outputs
- One data model → **PDF + DOCX + HTML** export.
- Three report variants, each tuned to its audience:
  - **Technical / Combined** — full detail: per-finding cards, vulnerabilities-by-host and (when enabled) the complete compliance mapping table with one column per framework.
  - **Executive** — lean: findings summary, status table, vulnerabilities-by-host, remediation and a **high-level compliance table** (priority finding × security domain). No full technical-findings section.
- Corporate cover page, provider logo banner, per-page header/footer with the **provider** identity, optional **CONFIDENTIAL** watermark.
- Automatic **Table of Contents** with dotted leaders and dynamic, sequential section numbering (no gaps or duplicate numbers when optional sections are absent).
- Separate **Executive Conclusion** export (DOCX + PDF): a 2–3 page management summary — metadata, overall-risk banner, security level, impact table, remediation-directions table and (opt-in) a high-level **priority-findings × domain** table. Metadata, findings counts, overall risk and posture auto-fill from the report; the intro, narrative and remediation-directions are editable from the UI.

### Findings import
Automatic parsing and field mapping from:
- **Nessus** (`.nessus` XML)
- **OpenVAS / Greenbone** XML
- **Nmap** XML
- **CSV** (custom)
- **JSON** (custom)

Severity, title, host(s), ports, CVSS score/vector, CVE/CWE and description/impact/recommendation are auto-mapped where available.

### Findings editor
- Full per-finding editing (title, severity, CVSS score & vector, hosts, ports, CVEs, CWEs, description, impact, recommendation, references, code/output).
- Evidence **images** (base64, auto-resized) and formatted code blocks.
- CVSS vector suggestions and auto-scoring.
- Per-finding **status** (Present / Resolved / Risk accepted / Open) and **exploitability** (Easy / Medium / Hard), for retest tracking.

### NIS-oriented report elements
- **Security posture verdict** with a five-level scale (Excellent → Inadequate) in the executive summary.
- **Impact × Exploitability = Risk** model rendered as colored bars per finding.
- **Current vulnerability status** table (per-finding state, location, comments, last update).
- Legal framing referencing **Law 362/2018 (NIS)** and **DNSC Order 559/2021**, plus CVSS.
- Standardized per-finding block: severity badge, CVSS vector, affected location.

### Compliance & control mapping
A complete, offline control library (`util/control_mapper.py`) covering:
- **NIS2** (Art. 21(2))
- **ISO/IEC 27001:2022** (Annex A)
- **NIST CSF 2.0**
- **NIST SP 800-53**
- **IEC 62443-3-3** (OT/ICS, opt-in)

Findings are **auto-classified** into security domains/categories (Access Control, Authentication, Vulnerability Management, Patch Management, Network Security, Cryptography, Logging & Monitoring, Asset Management, Backup & Recovery, Third-Party Risk, plus OT/ICS categories) on import, and can be **manually mapped/overridden** per finding from the web UI. Short acronyms (e.g. `sis`, `plc`, `rce`) are matched as whole tokens to avoid false positives inside longer words.

Compliance is **opt-in** — nothing is exported unless *Include compliance* is ticked in the Compliance tab, and only the frameworks you select are shown. Two views are produced:
- **Technical / Combined** — the full mapping table (every finding, one column per selected framework) plus a control legend (ID + title).
- **Executive report & Executive Conclusion** — a concise, high-level table: **priority finding × severity × security domain**. The detailed control mapping stays in the technical report.

### Bilingual (EN / RO)
Both the UI and the generated report follow the selected `report_language`. All strings live in `util/i18n.py`; Romanian output uses embedded fonts for correct diacritics.

### Editable fixed sections
Boilerplate text is centralized in one editable file per section, imported by all three generators (edit once, applies everywhere, in EN and RO):
- `util/legal_sections.py` — Confidentiality & legal (sections 1.0–1.2)
- `util/methodology.py` — Methodology (intro, standards, example tools)
- `util/attack_chain.py` — Attack Chain (intro, stages, limitation)

Per-report overrides in the saved JSON still take precedence where supported.

---

## Report structure

Section numbers are assigned dynamically, so they stay sequential regardless of which optional sections render.

**Technical / Combined**

```
1.0  Confidentiality & legal (1.1 statement, 1.2 disclaimer, 1.3 contacts)
2.0  Executive summary        (posture verdict, risk matrix)
  2.1  Assessment details     (scope, exclusions, client allowances)
  2.2  Attack chain           (fixed, generic)
  2.3  Methodology            (fixed, generic; bilingual NIS impact scale)
3.0  Findings summary         (3.1 current vulnerability status, 3.2 risk charts)
4.0  Vulnerabilities by host
5.0  Technical findings        (full per-finding cards)
6.0  Remediation plan
 ..  Detailed walkthrough / Additional reports (optional)
 ..  Compliance mapping (opt-in — full table)
```

**Executive** (lean — omits the full technical-findings section)

```
1.0  Confidentiality & legal
2.0  Executive summary        (2.1 details, 2.2 attack chain, 2.3 methodology)
3.0  Findings summary         (3.1 status, 3.2 charts)
4.0  Vulnerabilities by host
5.0  Remediation plan
6.0  Compliance mapping (opt-in — high-level domain table)
```

---

## Requirements

- **Python 3.10+**
- Dependencies (see `requirements.txt`):
  `streamlit`, `plotly`, `pandas`, `reportlab`, `python-docx`, `lxml`, `Pillow`, `matplotlib`, `Jinja2`

---

## Installation

```bash
git clone <your-repo-url>
cd PentestReportTemplate
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Launch the app (checks dependencies, then starts Streamlit):

```bash
python run.py
```

Or run Streamlit directly:

```bash
streamlit run app.py
```

Then open the local URL Streamlit prints (default `http://localhost:8501`).

**Workflow:** General info → Scope → import/add Findings → (optional) Additional reports & Detailed walkthrough → Executive summary → Remediation → Compliance/Controls → Export. The Export tab produces PDF / DOCX / HTML for the chosen variant; everything you filled in is saved to `data/saved_report.json`, which can be re-imported later to continue.

---

## Project structure

```
app.py                     Streamlit entry point (10 tabs)
run.py                     Launcher (dependency check + start)
requirements.txt

report/
  data_model.py            Canonical report schema / defaults
  parsers.py               Nessus / OpenVAS / Nmap / CSV / JSON import
  pdf_generator.py         PDF (ReportLab)
  docx_generator.py        DOCX (python-docx)
  html_generator.py        HTML (Jinja2)
  numbering.py             Finding / section numbering helpers

ui/
  general_info.py          Client, provider, logo, contacts, posture, test type
  scope_tab.py             Assessment overview / scope / exclusions / allowances
  findings_tab.py          Import + findings editor (status, exploitability, CVSS)
  additional_reports.py
  detailed_walkthrough_tab.py
  executive_summary_tab.py
  remediation_summary_tab.py
  compliance_tab.py
  conclusion_tab.py        Edit Executive Conclusion (intro, narrative, directions)
  export_tab.py            Choose variant + export PDF/DOCX/HTML + Executive Conclusion, load/save JSON

util/
  i18n.py                  EN/RO strings + get_language()
  control_mapper.py        Control library (NIS2/ISO/NIST/IEC) + auto-classifier
  compliance.py            Compliance mapping helpers
  report_meta.py           Status / exploitability / posture vocabularies
  legal_sections.py        Fixed legal texts (EN/RO)
  methodology.py           Fixed methodology content (EN/RO)
  attack_chain.py          Fixed attack-chain content (EN/RO)
  exec_conclusion.py       Executive Conclusion content + auto-fill logic (EN/RO)
  narrative.py             Executive-summary narrative generator
  charting.py              Severity distribution chart
  cvss_utils.py            CVSS parsing / scoring / vector suggestions
  severity.py, helpers.py, json_utils.py
  fonts/                   DejaVu fonts (diacritics)

tests/                     pytest suite
data/                      Saved report JSON, compliance mapping, previews
```

---

## Customizing the fixed texts

Edit the relevant file and keep the two languages in sync:

| Section | File | Keys |
|--------|------|------|
| Confidentiality & legal (1.0–1.2) | `util/legal_sections.py` | `SECTION_DEFAULTS["en"|"ro"]` |
| Methodology (intro / standards / tools) | `util/methodology.py` | `INTRO`, `STANDARDS`, `TOOLS`, ... |
| Attack chain (intro / stages / limitation) | `util/attack_chain.py` | `INTRO`, `STAGES`, `LIMITATION` |
| Executive Conclusion (impact table, auto-fill defaults) | `util/exec_conclusion.py` | `IMPACT_ROWS`, `default_intro`, `default_narrative`, `default_directions` |

UI labels and headings are in `util/i18n.py`.

---

## Sample data

Two fully-populated example reports are included (every field filled, evidence images, mapped controls) for quick testing:
- `data/demo.json` — Romanian
- `data/demo_en.json` — English

Load either from **Export → Load JSON**.

---

## Testing

```bash
python -m pytest tests/ -q
```

The suite covers parsers (incl. Nessus host-mapping regression), CVSS utilities, severity normalization, compliance mapping, control-library catalog consistency, and narrative generation.

---

## Notes on accuracy & scope

Reports describe what was actually performed. Labels such as "qualified NIS audit" or "DNSC-accredited auditor" must only be used if the issuing organization actually holds that accreditation — the template does not assert it. The Attack Chain section is explicitly analytical/hypothetical; active exploitation, credential attacks, privilege escalation and lateral movement are noted as not performed unless documented in the findings.

---

## License

Add your license of choice (e.g. MIT) as a `LICENSE` file. For authorized penetration testing and lab use only.
