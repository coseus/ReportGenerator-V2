from __future__ import annotations

import streamlit as st
import pandas as pd

from util import exec_conclusion as EC
from util.i18n import get_language


def _ensure(key, default):
    if key not in st.session_state:
        st.session_state[key] = default


def render_conclusion_tab(report_data: dict) -> dict:
    if not isinstance(report_data, dict):
        report_data = {}
    lang = get_language(report_data)

    st.header("Executive Conclusion")
    st.caption(
        "Short management-facing document, exported separately (DOCX + PDF). Metadata, "
        "findings counts, overall risk and security level are filled automatically from the "
        "report. The texts below are editable — leave a field empty to use the auto-generated version."
    )

    # Auto preview
    with st.expander("Auto preview (from report data)", expanded=False):
        st.write(f"**Overall risk:** {EC.risk(report_data, lang)[0]}")
        pl = EC.posture_line(report_data, lang)
        st.write(f"**{pl}**" if pl else "_Security level not set (General Info tab)._")
        for label, value in EC.metadata_rows(report_data, lang):
            st.write(f"- **{label}:** {value}")

    col1, col2 = st.columns(2)
    with col1:
        report_data["test_period"] = st.text_input(
            "Testing period", value=report_data.get("test_period", ""), key="concl_test_period",
            help="e.g. 9 September 2026, 16:50 – 11 September 2026, 12:07 EEST",
        )
    with col2:
        report_data["classification"] = st.text_input(
            "Classification", value=report_data.get("classification", ""), key="concl_classification",
            placeholder=EC.DEFAULT_CLASSIFICATION.get(lang, ""),
        )

    # Intro paragraphs
    st.subheader("Introductory summary")
    _ensure("concl_intro", report_data.get("conclusion_intro", ""))
    if st.button("Fill with auto-generated text", key="concl_intro_auto"):
        st.session_state["concl_intro"] = "\n\n".join(EC.default_intro(report_data, lang))
        st.rerun()
    report_data["conclusion_intro"] = st.text_area(
        "Intro paragraphs (separate paragraphs with a blank line)", height=180, key="concl_intro",
        help="Leave empty to use the auto-generated version.",
    )

    # Narrative
    st.subheader("Executive conclusion (narrative)")
    _ensure("concl_narrative", report_data.get("conclusion_narrative", ""))
    if st.button("Fill with auto-generated text", key="concl_narr_auto"):
        st.session_state["concl_narrative"] = "\n\n".join(EC.default_narrative(report_data, lang))
        st.rerun()
    report_data["conclusion_narrative"] = st.text_area(
        "Narrative", height=180, key="concl_narrative",
        help="Leave empty to use the auto-generated version.",
    )

    # Remediation directions table
    st.subheader("Remediation directions")
    st.caption("Editable table. Starts from the top findings; adjust freely.")
    dirs = report_data.get("remediation_directions") or EC.default_directions(report_data, lang)
    df = pd.DataFrame(dirs, columns=["direction", "intervention", "urgency"])
    edited = st.data_editor(
        df, num_rows="dynamic", width="stretch", key="concl_directions",
        column_config={
            "direction": st.column_config.TextColumn("Remediation direction", width="large"),
            "intervention": st.column_config.TextColumn("Intervention type", width="medium"),
            "urgency": st.column_config.TextColumn("Urgency", width="small"),
        },
    )
    try:
        records = edited.to_dict("records")
    except Exception:
        records = dirs
    report_data["remediation_directions"] = [
        r for r in records if str(r.get("direction", "")).strip()
    ]

    st.info("Export it from the **Export** tab → *Executive Conclusion* (DOCX / PDF).")
    return report_data
