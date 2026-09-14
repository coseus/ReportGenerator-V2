# -*- coding: utf-8 -*-
"""Executive Conclusion (Concluzie executivă) content and helpers.

A short management-facing deliverable, exported separately from the full
technical report. Auto-fills metadata, findings counts, overall risk and
security level from the report; the intro paragraphs, the conclusion narrative
and the remediation-directions table are editable from the web UI (with the
auto-generated text used as the default when the fields are empty). The impact
table and the compliance-implications text below are fixed boilerplate.
"""

from util import report_meta as RM
from util.i18n import get_language

SEVERITY_ORDER = ["Critical", "High", "Moderate", "Low", "Informational"]

# --- Overall risk label from the highest severity present ---
RISK_LABEL = {
    "Critical": {"ro": "CRITIC", "en": "CRITICAL"},
    "High": {"ro": "RIDICAT", "en": "HIGH"},
    "Moderate": {"ro": "MEDIU", "en": "MEDIUM"},
    "Low": {"ro": "SCĂZUT", "en": "LOW"},
    "Informational": {"ro": "SCĂZUT", "en": "LOW"},
}
RISK_COLOR = {"Critical": "#A61B1B", "High": "#D35400", "Moderate": "#B9770E",
              "Low": "#1F618D", "Informational": "#1F618D"}
RISK_DESC = {
    "ro": ("Evaluarea a identificat expuneri externe care permit accesul direct din Internet către "
           "servicii administrative și infrastructuri care în mod normal ar trebui accesate exclusiv "
           "din rețeaua internă sau prin VPN."),
    "en": ("The assessment identified external exposures allowing direct Internet access to administrative "
           "services and infrastructure that should normally be reachable only from the internal network or via VPN."),
}

TITLE = {"ro": "CONCLUZIE EXECUTIVĂ", "en": "EXECUTIVE CONCLUSION"}

# --- Fixed: impact table ---
IMPACT_HEADER = {"ro": ("Domeniu", "Impact potențial"), "en": ("Area", "Potential impact")}
IMPACT_ROWS = {
    "ro": [
        ("Confidențialitate", "Acces neautorizat la date și informații operaționale"),
        ("Integritate", "Modificarea neautorizată a configurațiilor sau a datelor"),
        ("Disponibilitate", "Întreruperea serviciilor expuse în Internet"),
        ("Operațional", "Creșterea riscului de compromitere a sistemelor interne"),
        ("Conformitate", "Posibile neconformități față de cerințele de securitate cibernetică aplicabile și față de politicile interne"),
    ],
    "en": [
        ("Confidentiality", "Unauthorized access to organizational data and operational information"),
        ("Integrity", "Unauthorized modification of configurations or data"),
        ("Availability", "Disruption of Internet-exposed services"),
        ("Operational", "Increased risk of compromise of internal systems"),
        ("Compliance", "Potential non-conformities against applicable cybersecurity requirements and internal policies"),
    ],
}

# --- Fixed: remediation-directions intro + table header ---
REMEDIATION_INTRO = {
    "ro": ("Urgența reflectă severitatea constatărilor. Tipul de intervenție indică natura efortului necesar; "
           "dimensionarea acestuia și planificarea efectivă rămân în sarcina echipelor {client}, în funcție de "
           "procedurile interne de schimbare."),
    "en": ("Urgency reflects the severity of the findings. The intervention type indicates the nature of the effort "
           "required; its sizing and actual planning remain the responsibility of the {client} teams, according to "
           "their internal change procedures."),
}
DIRECTIONS_HEADER = {
    "ro": ("#", "Direcție de remediere", "Tip de intervenție", "Urgență"),
    "en": ("#", "Remediation direction", "Intervention type", "Urgency"),
}

# --- Fixed: compliance implications paragraphs ---
COMPLIANCE = {
    "ro": [
        "Constatările identificate indică deficiențe care pot afecta nivelul general de securitate al mediului "
        "evaluat și pot avea impact asupra conformității cu cerințele legale, de reglementare, contractuale și "
        "organizaționale aplicabile în domeniul securității cibernetice.",
        "Observațiile se referă la domenii de securitate abordate în mod uzual de cadrele de securitate cibernetică, "
        "de standardele din industrie și de cerințele de reglementare, incluzând managementul vulnerabilităților, "
        "controlul accesului, mecanismele de autentificare, configurarea sigură a sistemelor, protecția serviciilor "
        "expuse în Internet, monitorizarea, jurnalizarea și guvernanța securității.",
        "Organizațiile ar trebui să evalueze constatările identificate în contextul propriilor obiective de management "
        "al riscului, de conformitate și de securitate. Remedierea problemelor raportate poate reduce riscul de securitate "
        "cibernetică, poate îmbunătăți reziliența față de amenințările potențiale și poate susține inițiativele continue "
        "de conformitate și de îmbunătățire a securității.",
        "Această activitate a fost realizată ca o evaluare de securitate. În funcție de scopul și metodologia convenite, "
        "activitățile pot include identificarea vulnerabilităților, revizuirea configurațiilor, validarea de securitate și "
        "tehnici controlate de testare de penetrare. Toate activitățile de testare au fost desfășurate în cadrul scopului "
        "autorizat și în conformitate cu regulile de angajament. Nu au fost efectuate intenționat modificări asupra "
        "sistemelor de producție, a datelor sau a proceselor de business, dincolo de acțiunile necesare pentru validarea "
        "constatărilor identificate.",
        "Informațiile tehnice detaliate, evidențele justificative, evaluările de risc și recomandările de remediere sunt "
        "prezentate în raportul tehnic însoțitor.",
    ],
    "en": [
        "The identified findings indicate weaknesses that may affect the overall security posture of the assessed "
        "environment and could impact compliance with applicable legal, regulatory, contractual, and organizational "
        "cybersecurity requirements.",
        "The observations relate to security domains commonly addressed by cybersecurity frameworks, industry standards, "
        "and regulatory requirements, including vulnerability management, access control, authentication mechanisms, "
        "secure system configuration, protection of Internet-facing services, monitoring, logging, and security governance.",
        "Organizations should assess the identified findings in the context of their specific risk management, compliance, "
        "and security objectives. Addressing the reported issues can reduce cybersecurity risk, improve resilience against "
        "potential threats, and support ongoing compliance and security improvement initiatives.",
        "This engagement was performed as a security assessment. Depending on the agreed scope and methodology, activities "
        "may have included vulnerability identification, configuration review, security validation, and controlled "
        "penetration testing techniques. All testing activities were conducted within the authorized scope and in "
        "accordance with the engagement rules. No changes to production systems, data, or business processes were "
        "intentionally performed beyond the actions required to validate identified findings.",
        "Detailed technical information, supporting evidence, risk ratings, and remediation recommendations are provided "
        "in the accompanying technical report.",
    ],
}
DEFAULT_CLASSIFICATION = {"ro": "Confidențial — distribuție limitată", "en": "Confidential — limited distribution"}
URGENCY = {
    "Critical": {"ro": "Imediată", "en": "Immediate"},
    "High": {"ro": "Ridicată", "en": "High"},
    "Moderate": {"ro": "Planificată", "en": "Planned"},
    "Low": {"ro": "Recomandată", "en": "Recommended"},
    "Informational": {"ro": "Opțională", "en": "Optional"},
}


def _pick(table, lang):
    return table.get(lang) or table["en"]


def _counts(report):
    c = {s: 0 for s in SEVERITY_ORDER}
    for f in report.get("findings", []) or []:
        s = f.get("severity", "Informational")
        c[s if s in c else "Informational"] += 1
    return c


def highest_severity(report):
    c = _counts(report)
    return next((s for s in SEVERITY_ORDER if c[s] > 0), "Informational")


def risk(report, lang="en"):
    """(label, color, description) for the overall risk banner."""
    sev = highest_severity(report)
    return _pick(RISK_LABEL[sev], lang), RISK_COLOR[sev], _pick(RISK_DESC, lang)


def title(lang="en"):
    return _pick(TITLE, lang)


def subtitle(report, lang="en"):
    proj = str(report.get("project") or "").strip()
    if proj:
        return proj
    return "Evaluare de vulnerabilități — perimetru extern" if lang == "ro" else "Vulnerability assessment — external perimeter"


def metadata_rows(report, lang="en"):
    ro = lang == "ro"
    client = str(report.get("client") or "").strip()
    provider = str(report.get("provider") or "").strip()
    tester = str(report.get("tester") or "").strip()
    contact = str(report.get("contact") or "").strip()
    test_type = str(report.get("test_type") or "Black Box").strip()
    project = str(report.get("project") or "").strip()
    version = str(report.get("version") or "1.0").strip()
    date = str(report.get("date") or "").strip()
    period = str(report.get("test_period") or "").strip() or date
    classification = str(report.get("classification") or "").strip() or _pick(DEFAULT_CLASSIFICATION, lang)
    executed = " — ".join([p for p in [provider, tester] if p]) or provider or tester
    if contact:
        executed = f"{executed} ({contact})" if executed else contact
    eval_desc = project or ("Vulnerability Assessment" if not ro else "Vulnerability Assessment")
    eval_desc = f"{eval_desc}, {'tip' if ro else 'type'} {test_type}"
    L = {
        "ro": ["Client", "Evaluare", "Executat de", "Perioada testării", "Versiune / dată", "Clasificare"],
        "en": ["Client", "Assessment", "Performed by", "Testing period", "Version / date", "Classification"],
    }
    labels = _pick(L, lang)
    vals = [client or "-", eval_desc, executed or "-", period or "-",
            f"{version} — {date}" if date else version, classification]
    return list(zip(labels, vals))


def impact_header(lang="en"):
    return _pick(IMPACT_HEADER, lang)


def impact_rows(lang="en"):
    return list(_pick(IMPACT_ROWS, lang))


def remediation_intro(report, lang="en"):
    return _pick(REMEDIATION_INTRO, lang).format(client=str(report.get("client") or "").strip() or ("organizației" if lang == "ro" else "the organization"))


def directions_header(lang="en"):
    return _pick(DIRECTIONS_HEADER, lang)


def compliance_paras(report, lang="en"):
    # Neutral, standard-agnostic wording (covers both VA and penetration testing).
    return list(_pick(COMPLIANCE, lang))


def posture_line(report, lang="en"):
    key = RM.posture_key(report)
    if not key:
        return ""
    label = RM.posture_label(report, lang)
    desc = RM.POSTURE_DESC.get(lang, RM.POSTURE_DESC.get("en", {})).get(key, "")
    head = "Nivel general de securitate" if lang == "ro" else "Overall security level"
    return f"{head}: {label} — {desc}" if desc else f"{head}: {label}"


# ---------- Editable content: report override OR auto-generated default ----------
def _split_paras(text):
    return [p.strip() for p in str(text).replace("\r\n", "\n").split("\n\n") if p.strip()]


def default_intro(report, lang="en"):
    if lang == "ro":
        return [
            "Cea mai importantă constatare este expunerea directă în Internet a unor servicii administrative și a unor "
            "componente software critice, care în mod normal ar trebui accesate exclusiv din rețeaua internă sau prin VPN.",
            "În cazul compromiterii acestor sisteme, există posibilitatea accesului neautorizat la datele organizației, "
            "a compromiterii sistemelor critice și a utilizării infrastructurii ca punct de intrare către alte segmente interne.",
            "Deși în cadrul evaluării nu au fost identificate vulnerabilități exploatabile imediat, fără autentificare, și nu "
            "au fost efectuate exploatări active, suprafața de atac expusă este semnificativ mai mare decât nivelul recomandat "
            "de bunele practici de securitate.",
        ]
    return [
        "The most important finding is the direct Internet exposure of administrative services and critical software "
        "components that should normally be reachable only from the internal network or via VPN.",
        "Should these systems be compromised, there is potential for unauthorized access to organizational data, compromise "
        "of critical systems, and use of the infrastructure as an entry point toward other internal segments.",
        "Although no immediately exploitable, unauthenticated vulnerabilities were identified during the assessment and no "
        "active exploitation was performed, the exposed attack surface is significantly larger than the level recommended by "
        "security good practices.",
    ]


def _counts_sentence(report, lang):
    c = _counts(report)
    total = sum(c.values())
    if lang == "ro":
        def w(n, sing, plur):
            return f"{n} {sing if n == 1 else plur}"
        parts = [w(c["Critical"], "critică", "critice"), w(c["High"], "ridicată", "ridicate"),
                 w(c["Moderate"], "moderată", "moderate"), w(c["Low"], "scăzută", "scăzute"),
                 w(c["Informational"], "observație", "observații")]
        noun = "constatare de securitate" if total == 1 else "constatări de securitate"
        return f"Au fost identificate {total} {noun}: " + ", ".join(parts[:-1]) + " și " + parts[-1] + "."
    noun = "finding" if total == 1 else "findings"
    return (f"A total of {total} security {noun} were identified: {c['Critical']} critical, {c['High']} high, "
            f"{c['Moderate']} moderate, {c['Low']} low and {c['Informational']} informational.")


def default_narrative(report, lang="en"):
    client = str(report.get("client") or "").strip() or ("organizației" if lang == "ro" else "the organization")
    risk_label = risk(report, lang)[0]
    if lang == "ro":
        return [
            f"Evaluarea de vulnerabilități a perimetrului extern {client} a identificat un nivel general de risc {risk_label}, "
            "determinat în principal de expunerea directă în Internet a unor servicii administrative și a unor componente "
            "software aflate la sfârșitul ciclului de suport.",
            _counts_sentence(report, lang),
            "Majoritatea riscurilor identificate nu necesită modificări ale aplicațiilor și pot fi remediate prin măsuri de "
            "securitate la nivelul infrastructurii și al echipamentelor de perimetru. O reducere semnificativă a riscului poate "
            "fi obținută într-un interval scurt prin eliminarea accesului public către serviciile de administrare și bazele de "
            "date, restricționarea accesului administrativ exclusiv prin VPN și autentificare multifactor și revizuirea regulilor "
            "de filtrare și a expunerilor existente.",
        ]
    return [
        f"The external-perimeter vulnerability assessment of {client} identified an overall risk level of {risk_label}, driven "
        "mainly by the direct Internet exposure of administrative services and of software components that have reached the end "
        "of their support lifecycle.",
        _counts_sentence(report, lang),
        "Most of the identified risks do not require application changes and can be remediated through security measures at the "
        "infrastructure and perimeter level. A significant reduction in risk can be achieved in a short timeframe by removing "
        "public access to administrative services and databases, restricting administrative access to VPN with multi-factor "
        "authentication, and reviewing existing filtering rules and exposures.",
    ]


def default_directions(report, lang="en"):
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(report.get("findings", []) or [],
                      key=lambda f: order.get(f.get("severity", "Informational"), 99))
    rows = []
    for f in findings[:6]:
        sev = f.get("severity", "Informational")
        rows.append({
            "direction": str(f.get("title") or "-"),
            "intervention": "Configurare la nivelul echipamentelor de perimetru" if lang == "ro"
                            else "Configuration at the perimeter devices",
            "urgency": _pick(URGENCY.get(sev, URGENCY["Informational"]), lang),
        })
    rows.append({
        "direction": "Scanare de verificare după remediere" if lang == "ro" else "Verification scan after remediation",
        "intervention": "Reluarea evaluării pe aceleași sisteme" if lang == "ro" else "Re-assessment of the same systems",
        "urgency": "După remediere" if lang == "ro" else "After remediation",
    })
    return rows


def intro(report, lang="en"):
    custom = str(report.get("conclusion_intro") or "").strip()
    return _split_paras(custom) if custom else default_intro(report, lang)


def narrative(report, lang="en"):
    custom = str(report.get("conclusion_narrative") or "").strip()
    return _split_paras(custom) if custom else default_narrative(report, lang)


def directions(report, lang="en"):
    custom = report.get("remediation_directions")
    if isinstance(custom, list) and custom:
        out = []
        for r in custom:
            if isinstance(r, dict):
                out.append({"direction": str(r.get("direction") or "").strip(),
                            "intervention": str(r.get("intervention") or "").strip(),
                            "urgency": str(r.get("urgency") or "").strip()})
        if any(r["direction"] for r in out):
            return out
    return default_directions(report, lang)


SECTIONS = {
    "ro": {
        "conclusion": "Concluzie executivă",
        "impact": "Impact potențial asupra organizației",
        "remediation": "Direcții de remediere, urgență și tip de efort",
        "compliance": "Implicații de conformitate",
        "mapping": "Constatări prioritare și domenii de securitate",
        "risk_general": "RISC GENERAL",
    },
    "en": {
        "conclusion": "Executive conclusion",
        "impact": "Potential impact on the organization",
        "remediation": "Remediation directions, urgency and effort type",
        "compliance": "Compliance implications",
        "mapping": "Priority findings and security domains",
        "risk_general": "OVERALL RISK",
    },
}


def section(key, lang="en"):
    table = SECTIONS.get(lang) or SECTIONS["en"]
    return table.get(key, key)


MAPPING_LEAD = {
    "ro": ("Tabelul de mai jos rezumă constatările cu cel mai ridicat nivel de risc și domeniile de "
           "securitate asociate. Maparea detaliată către cerințe și controale este prezentată în raportul tehnic."),
    "en": ("The table below summarizes the highest-risk findings and the associated security domains. "
           "The detailed mapping to requirements and controls is provided in the technical report."),
}
MAPPING_HEADER = {
    "ro": ("Constatare prioritară", "Severitate", "Domeniu"),
    "en": ("Priority finding", "Severity", "Domain"),
}


def mapping_lead(lang="en"):
    return _pick(MAPPING_LEAD, lang)


def mapping_header(lang="en"):
    return _pick(MAPPING_HEADER, lang)


def compliance_mapping_rows(report, lang="en", max_findings=6, max_domains=2):
    """High-level view: the most-severe findings with their security domains
    (finding categories). The detailed control mapping stays in the technical
    report. Gated by the include_compliance flag; empty when disabled.
    Returns [{"title", "severity", "domain"}]."""
    if not report.get("include_compliance", False):
        return []
    try:
        from util import control_mapper as CM
    except Exception:
        return []
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    all_findings = report.get("findings", []) or []
    severe = [f for f in all_findings if f.get("severity") in ("Critical", "High")]
    pool = severe if severe else all_findings
    pool = sorted(pool, key=lambda f: order.get(f.get("severity", "Informational"), 99))[:max_findings]
    rows = []
    for f in pool:
        cats = [c for c in (f.get("categories") or CM.classify_finding(f)) if c][:max_domains]
        rows.append({"title": f.get("title") or "-",
                     "severity": f.get("severity") or "Informational",
                     "domain": " / ".join(cats) if cats else "-"})
    return rows
