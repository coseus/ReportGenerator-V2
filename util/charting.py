from __future__ import annotations

from io import BytesIO
import base64
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEV_ORDER = ["Critical", "High", "Moderate", "Low", "Informational"]
WEIGHTS = {"Critical": 5, "High": 4, "Moderate": 3, "Low": 2, "Informational": 1}

def _fig_to_png_bytes(fig) -> bytes:
    bio = BytesIO()
    fig.savefig(bio, format="png", bbox_inches="tight", dpi=150)
    plt.close(fig)
    bio.seek(0)
    return bio.read()

def severity_distribution_png(summary_counts: dict[str,int]) -> bytes:
    counts = [int(summary_counts.get(sev, 0)) for sev in SEV_ORDER]
    fig, ax = plt.subplots(figsize=(6.8, 3.5))
    ax.bar(SEV_ORDER, counts)
    ax.set_title("Severity Distribution")
    ax.set_ylabel("Count")
    ax.set_xlabel("Severity")
    for idx, val in enumerate(counts):
        ax.text(idx, val + 0.05, str(val), ha='center', va='bottom', fontsize=8)
    fig.tight_layout()
    return _fig_to_png_bytes(fig)

def risk_trend_png(findings: list[dict]) -> bytes:
    x = list(range(1, len(findings) + 1)) or [1]
    running = []
    total = 0
    for item in findings:
        total += WEIGHTS.get(item.get("severity"), 1)
        running.append(total)
    if not running:
        running = [0]
    fig, ax = plt.subplots(figsize=(6.8, 3.5))
    ax.plot(x, running, marker='o')
    ax.set_title("Risk Trend")
    ax.set_ylabel("Cumulative Risk")
    ax.set_xlabel("Finding Order")
    fig.tight_layout()
    return _fig_to_png_bytes(fig)

def png_bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')
