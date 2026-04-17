from __future__ import annotations

import math
import re
from typing import Any

VECTOR_RE = re.compile(r"CVSS:3\.[01]/")

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
SCOPE = {"U", "C"}
CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}

def _round_up_1(x: float) -> float:
    return math.ceil(x * 10) / 10.0

def parse_vector(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not VECTOR_RE.match(vector.strip()):
        raise ValueError("Unsupported CVSS vector. Expected CVSS:3.0 or CVSS:3.1")
    parts = vector.strip().split('/')
    metrics = {}
    for part in parts[1:]:
        if ':' in part:
            k, v = part.split(':', 1)
            metrics[k] = v
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [k for k in required if k not in metrics]
    if missing:
        raise ValueError(f"Missing CVSS metrics: {', '.join(missing)}")
    return metrics

def calculate_cvss31(vector: str) -> tuple[float, str]:
    m = parse_vector(vector)
    av = AV[m["AV"]]
    ac = AC[m["AC"]]
    pr = PR_C[m["PR"]] if m["S"] == "C" else PR_U[m["PR"]]
    ui = UI[m["UI"]]
    c = CIA[m["C"]]
    i = CIA[m["I"]]
    a = CIA[m["A"]]
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif m["S"] == "U":
        score = _round_up_1(min(impact + exploitability, 10))
    else:
        score = _round_up_1(min(1.08 * (impact + exploitability), 10))
    return score, severity_from_score(score)

def severity_from_score(score: Any) -> str:
    try:
        score = float(score)
    except Exception:
        return "Informational"
    if score == 0:
        return "Informational"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Moderate"
    if score > 0:
        return "Low"
    return "Informational"

def auto_fill_finding_cvss(finding: dict) -> dict:
    finding = dict(finding or {})
    vector = str(finding.get("cvss_vector") or "").strip()
    if not vector:
        return finding
    try:
        score, sev = calculate_cvss31(vector)
        if not str(finding.get("cvss") or "").strip():
            finding["cvss"] = f"{score:.1f}"
        if not str(finding.get("severity") or "").strip() or finding.get("severity") == "Informational":
            finding["severity"] = sev
        finding["cvss_auto_score"] = f"{score:.1f}"
        finding["cvss_auto_severity"] = sev
        finding["cvss_auto_ok"] = True
    except Exception as exc:
        finding["cvss_auto_ok"] = False
        finding["cvss_auto_error"] = str(exc)
    return finding
