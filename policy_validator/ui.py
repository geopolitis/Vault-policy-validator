from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, List, Tuple
import streamlit as st
try:
    from .parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from .priority import cohort_and_caps, decide
    from .lints import lint_overlaps, lint_risky, lint_commented_rules, aggregate_stats
    from . import Rule, Finding, Stats
except Exception:
    import sys, pathlib
    ROOT = pathlib.Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT))
    from policy_validator.parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import cohort_and_caps, decide
    from policy_validator.lints import lint_overlaps, lint_risky, lint_commented_rules, aggregate_stats
    from policy_validator import Rule, Finding, Stats

st.set_page_config(page_title="Vault Policy Validator", layout="wide", initial_sidebar_state="expanded")

def _split_errors(errors: List[str]) -> Tuple[List[str], List[str]]:
    """Return (fatal_errors, low_warnings)."""
    fat: List[str] = []
    low: List[str] = []
    for e in errors:
        (low if e.strip().lower().startswith("[low]") else fat).append(e)
    return fat, low

def _analyze_text(text: str, source: str) -> tuple[list[str], list[Rule], list[Finding]]:
    """Parse & lint. Never block; best-effort parsing always runs."""
    text = text or ""
    errs = hcl_syntax_check(text) if text.strip() else []
    rules = parse_vault_policy(text, source=source) if text.strip() else []
    finds: List[Finding] = []
    finds += lint_overlaps(rules)
    finds += lint_risky(rules)
    finds += lint_commented_rules({source: text})
    return errs, rules, finds

def _render_stats(stats: Stats) -> None:
    st.sidebar.markdown("### Statistics")
    st.sidebar.write(f"- Files searched: {stats.files}")
    st.sidebar.write(f"- Policies parsed: {stats.policies}")
    st.sidebar.write(f"- Syntax errors: {stats.syntax}")
    st.sidebar.write(f"- Overlapping ACL paths: {stats.overlaps}")
    st.sidebar.write(f"- High risk findings: {stats.high}")
    st.sidebar.write(f"- Low risk findings: {stats.low}")
    st.sidebar.write(f"- Risky findings: {stats.risky}")

def _render_findings(findings: List[Finding], severity_filter: str) -> None:
    if not findings:
        return
    visible = findings if severity_filter == "all" else [f for f in findings if f.severity == severity_filter]
    for f in visible:
        tag = f"[{f.severity}]"
        loc = f" ({f.source}:{f.lineno})" if f.source and f.lineno else ""
        msg = f"{tag} {f.code}: {f.message}{loc}"
        if f.severity == "high":
            st.error(msg)
        elif f.severity == "risky":
            st.warning(msg)
        else:
            st.info(msg)

# ---------------- sidebar ----------------

st.sidebar.title("Vault Policy Checker")
mode = st.sidebar.radio("Mode", ["Single file", "Scan folder"], index=0)
severity = st.sidebar.selectbox("Severity", ["all", "high", "risky", "low"], index=0)
st.sidebar.markdown("---")

# File actions are in the SIDEBAR now
if mode == "Single file":
    source = st.sidebar.radio("Source", ["Upload file", "Paste text"], index=1, key="source_choice")
    if source == "Upload file":
        uploaded = st.sidebar.file_uploader("Upload .hcl / .policy / .txt", type=["hcl", "policy", "txt"], key="uploader")
        load_clicked = st.sidebar.button("Load file", use_container_width=True)
        if uploaded and load_clicked:
            st.session_state["policy_text"] = uploaded.read().decode("utf-8", errors="replace")
else:
    st.sidebar.text("Folder scan")
    folder = st.sidebar.text_input("Folder path (server-side)", value=st.session_state.get("scan_folder", ""))
    st.session_state["scan_folder"] = folder
    exts = st.sidebar.text_input("Extensions (comma separated)", value=st.session_state.get("scan_exts", ".hcl,.policy,.txt"))
    st.session_state["scan_exts"] = exts
    scan_clicked = st.sidebar.button("Scan folder", use_container_width=True)

st.sidebar.markdown("---")

# Stats placeholder at first load
if "stats" not in st.session_state:
    st.session_state["stats"] = Stats()
_render_stats(st.session_state["stats"])

# ---------------- main page ----------------

st.header("Vault Policy Validation, Linting, and Analysis")

# MOVE Request Path & Capability to MAIN (not sidebar)
c1, c2 = st.columns([2, 1])
with c1:
    req_path = st.text_input("Request Path", value=st.session_state.get("req_path", ""), placeholder="e.g., secret/data/foo/bar")
    st.session_state["req_path"] = req_path
with c2:
    capability = st.selectbox("Capability", CAPABILITIES, index=0, key="capability_select")

if mode == "Single file":
    st.subheader("Single File")
    # Big editor always on main; pre-populated when user loads file from sidebar
    policy_text = st.text_area(
        "Policy (paste or edit here)",
        value=st.session_state.get("policy_text", ""),
        height=360,
        placeholder='path "kv/data/foo/*" { capabilities = ["read","list"] }',
        key="policy_editor",
    )

    analyze_clicked = st.button("Analyze", type="primary")

    if analyze_clicked:
        errs, rules, findings = _analyze_text(policy_text, source="inline")
        fatal, _ = _split_errors(errs)
        stats = aggregate_stats(findings, files=1, policies=len(rules), syntax_errors=len(fatal))
        st.session_state["stats"] = stats
        _render_stats(stats)

        st.subheader("Syntax")
        if errs:
            for e in errs:
                (st.error if not e.lower().startswith("[low]") else st.warning)(e)
        else:
            st.success("No syntax errors detected.")

        st.subheader("Findings")
        _render_findings(findings, severity)

        st.subheader("Decision")
        if req_path and st.session_state.get("capability_select"):
            cohort, caps = cohort_and_caps(rules, req_path)
            result = decide(rules, req_path, st.session_state["capability_select"])
            st.write(f"Decision: **{result}**")
            if cohort:
                with st.expander("Matched rules (highest specificity)"):
                    for r in cohort:
                        st.write(f"- `{r.path}` from **{r.source}** @ line {r.lineno} → {sorted(r.capabilities)}")
                st.caption(f"Effective caps on best path: `{', '.join(sorted(caps))}`")
        else:
            st.info("Enter a Path and Capability to test a decision.")

else:
    st.subheader("Scan Folder")
    if "scan_results" not in st.session_state:
        st.session_state["scan_results"] = None

    if 'scan_clicked_flag' not in st.session_state:
        st.session_state['scan_clicked_flag'] = False

    # If user pressed the sidebar button this run
    if 'scan_clicked' in locals() and scan_clicked:
        st.session_state['scan_clicked_flag'] = True

    if st.session_state['scan_clicked_flag']:
        base = Path(st.session_state.get("scan_folder") or "")
        include_exts = {e.strip().lower() for e in (st.session_state.get("scan_exts") or "").split(",") if e.strip()}

        texts: Dict[str, str] = {}
        all_errs: List[str] = []
        all_rules: List[Rule] = []
        all_findings: List[Finding] = []

        files: List[Path] = []
        if base.exists() and base.is_dir():
            for root, _, names in os.walk(base):
                for fn in names:
                    p = Path(root) / fn
                    if p.suffix.lower() in include_exts:
                        files.append(p)
        else:
            st.error("Folder not found or not a directory.")

        for fp in files:
            text = fp.read_text(encoding="utf-8", errors="replace")
            errs, rules, findings = _analyze_text(text, source=str(fp))
            texts[str(fp)] = text
            all_errs += errs
            all_rules += rules
            all_findings += findings

        fatal = [e for e in all_errs if not e.lower().startswith("[low]")]
        stats = aggregate_stats(all_findings, files=len(files), policies=len(all_rules), syntax_errors=len(fatal))
        st.session_state["stats"] = stats
        _render_stats(stats)

        st.subheader("Syntax")
        if all_errs:
            for e in all_errs:
                (st.error if not e.lower().startswith("[low]") else st.warning)(e)
        else:
            st.success("No syntax errors detected.")

        st.subheader("Findings")
        _render_findings(all_findings, severity)

        st.subheader("Decision Across Folder")
        if req_path and st.session_state.get("capability_select"):
            cohort, caps = cohort_and_caps(all_rules, req_path)
            result = decide(all_rules, req_path, st.session_state["capability_select"])
            st.write(f"Decision: **{result}**")
            if cohort:
                with st.expander("Matched rules (highest specificity)"):
                    for r in cohort:
                        st.write(f"- `{r.path}` from **{r.source}** @ line {r.lineno} → {sorted(r.capabilities)}")
                st.caption(f"Effective caps on best path: `{', '.join(sorted(caps))}`")
        else:
            st.info("Enter a Path and Capability to test a decision.")
    else:
        st.info("Set folder & extensions in the sidebar, then click **Scan folder**.")
