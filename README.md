# Pentest Report Generator

Pentest Report Generator este o aplicație Streamlit pentru generarea de rapoarte de penetration testing în format PDF, DOCX și HTML, cu suport pentru executive, technical și combined report.

## Funcționalități principale

* Export în:

  * PDF
  * DOCX
  * HTML
* Profiluri de raport:

  * Executive
  * Technical
  * Combined
* Multi-language:

  * English
  * Romanian
* CVSS auto-calculation din vector CVSS v3.x
* Grafice de risc:

  * Severity Distribution
  * Risk Trend
* Suport pentru:

  * Findings
  * Detailed Walkthrough
  * Additional Reports
  * Contact Information
  * Legal / Confidentiality sections
* Suport pentru imagini cu caption
* Suport pentru multiple:

  * Hosts
  * Ports
  * CVEs
  * CWEs

## Structură proiect

project/
├── app.py
├── run.py
├── build_exe.py
├── launcher.py
├── setup_paths.py
├── requirements.txt
├── data/
├── assets/
├── ui/
├── util/
│   ├── helpers.py
│   ├── i18n.py
│   ├── charting.py
│   └── cvss_utils.py
└── report/
├── pdf_generator.py
├── docx_generator.py
├── html_generator.py
└── sections/

## Cerințe

* Python 3.11+
* pip
* mediu virtual recomandat

## Instalare

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Pe Windows:

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

## Rulare locală

python run.py

sau direct:

streamlit run app.py

## Build executabil

python build_exe.py

## Date suportate în JSON

Aplicația folosește un obiect principal `report_data` care poate conține:

* client
* project
* date
* version
* tester
* theme_hex
* watermark_enabled
* report_language
* include_charts
* logo_b64
* executive_summary
* assessment_overview
* assessment_details
* scope
* scope_exclusions
* client_allowances
* attack_path
* contacts
* findings
* detailed_walkthrough
* additional_reports
* remediation_short
* remediation_medium
* remediation_long
* sections

## Secțiuni speciale

Secțiunile legale pot fi citite fie din top-level, fie din report["sections"]:

* section_1_0_confidentiality_and_legal
* section_1_1_confidentiality_statement
* section_1_2_disclaimer
* section_1_3_contact_information

Dacă lipsesc, unele au fallback implicit.

## Findings

Un finding poate conține:

* title
* severity
* cvss
* cvss_vector
* description
* likelihood
* impact
* tools_used
* recommendation
* references
* protocol
* code
* host / hosts
* port / ports
* cve / cves
* cwe / cwes
* images

Pentru compatibilitate, aplicația acceptă atât varianta singulară, cât și lista multiplă.

## Imagini

Imaginile sunt suportate în format base64 și pot avea caption:

{
"images": [
{
"data": "<base64>",
"name": "Caption imagine"
}
]
}

Caption-ul este centrat în PDF, DOCX și HTML.

## Export HTML

HTML export include:

* Cover / meta info
* Table of Contents
* Legal sections
* Overview
* Assessment Details
* Findings Summary
* Risk Charts
* Technical Findings
* Detailed Walkthrough
* Additional Reports

În HTML:

* conținutul este aliniat la stânga
* caption-urile imaginilor sunt centrate

## Multi-language

Limbile sunt gestionate prin util/i18n.py

Cheia principală din raport:

{
"report_language": "en"
}

Valori suportate:

* en
* ro

Se traduc etichetele generate de sistem. Conținutul scris manual de utilizator nu este tradus automat.

## CVSS auto-calculation

util/cvss_utils.py permite calcul automat al scorului CVSS din cvss_vector.

Exemplu:

{
"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}

Aplicația poate completa:

* cvss
* severity

## Charts

util/charting.py generează:

* Severity Distribution
* Risk Trend

Acestea sunt folosite în PDF și HTML când include_charts este activ.

## Observații DOCX

Cuprinsul din DOCX trebuie actualizat manual în Microsoft Word:

* click dreapta pe TOC
* Update Field

## Observații Streamlit

În versiunile noi de Streamlit:

* use_container_width=True → width="stretch"
* use_container_width=False → width="content"

## Recomandări

* șterge **pycache** dacă înlocuiești manual fișiere
* repornește aplicația după modificări
* păstrează backup înainte de modificări majore

## Status

Implementat:

* PDF export
* DOCX export
* HTML export
* Multi-language
* CVSS auto-calculation
* Charts
* Multi-value findings
* Image captions

## Autor

Pentest Report Generator – Corporate Edition
