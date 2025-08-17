from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import streamlit as st

try:
    from policy_validator.parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import check_policies
    from policy_validator.lints import (
        find_overlapping_acls, suggest_optimizations, risky_grants_lint,
        risk_counts, filter_by_severity,
    )
except Exception:
    from parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy   
    from priority import check_policies   
    from lints import (   
        find_overlapping_acls, suggest_optimizations, risky_grants_lint,
        risk_counts, filter_by_severity,
    )

st.set_page_config(page_title="Vault Policy Permission Checker", layout="wide", initial_sidebar_state="expanded")

# ---- Session defaults ----
def _init_state():
    st.session_state.setdefault("policy_text", "")
    st.session_state.setdefault("rules", [])
    st.session_state.setdefault("hcl_errors", [])
    st.session_state.setdefault("overlaps", {})
    st.session_state.setdefault("risky_msgs", [])
    st.session_state.setdefault("stats", {"files":0,"policies":0,"syntax":0,"overlaps":0,"high":0,"low":0,"risky":0})
    st.session_state.setdefault("request_path", "")
    st.session_state.setdefault("operation", CAPABILITIES[0])
    st.session_state.setdefault("load_clicked", False)
    st.session_state.setdefault("check_policy_clicked", False)
_init_state()

def _compute_and_store(policy_text: str) -> None:
    hcl_errors: List[str] = hcl_syntax_check(policy_text) if policy_text.strip() else []
    rules: List[Dict[str, Any]] = parse_vault_policy(policy_text) if not hcl_errors else []
    overlaps = find_overlapping_acls(rules) if rules else {}
    risky_msgs = risky_grants_lint(rules) if rules else []
    stats = {"files": 1 if policy_text.strip() else 0,
             "policies": len(rules),
             "syntax": len(hcl_errors),
             "overlaps": len(overlaps),
             **risk_counts(risky_msgs)}
    st.session_state.policy_text = policy_text
    st.session_state.rules = rules
    st.session_state.hcl_errors = hcl_errors
    st.session_state.overlaps = overlaps
    st.session_state.risky_msgs = risky_msgs
    st.session_state.stats = stats

def _show_stats_sidebar(stats: Dict[str, int], mode_label: str) -> None:
    with st.sidebar:
        st.markdown("---")
        st.markdown("### Statistics")
        st.write(f"- Mode: {mode_label}")
        st.write(f"- Files searched: {stats.get('files', 0)}")
        st.write(f"- Policies parsed: {stats.get('policies', 0)}")
        st.write(f"- Syntax errors: {stats.get('syntax', 0)}")
        st.write(f"- Overlapping ACL paths: {stats.get('overlaps', 0)}")
        st.write(f"- High risk findings: {stats.get('high', 0)}")
        st.write(f"- Low risk findings: {stats.get('low', 0)}")
        st.write(f"- Risky findings: {stats.get('risky', 0)}")

# ---- Sidebar (stable order: Mode → Load/Scan → Request → Filter → Stats) ----
with st.sidebar:
    st.title("Vault Policy Checker")

    mode = st.radio("Load Policy", ["Single file", "Scan folder"], index=0, key="mode")
    if mode == "Single file":
        source = st.radio("Source", ["Upload file", "Paste text"], index=0, key="source")
        if source == "Upload file":
            st.file_uploader("Policy file (.hcl, .txt)", type=["hcl", "txt"], key="uploaded_policy")
            st.button("Load File", key="btn_load_file", on_click=lambda: st.session_state.update(load_clicked=True))
        else:
            st.caption("Paste your policy in the big box on the main page and click **Check Policy**.")
    else:
        st.subheader("Scan a folder")
        st.text_input("Folder path (server-side)", value=st.session_state.get("folder_path",""), key="folder_path")
        st.text_input("Include extensions (comma-separated)", value=st.session_state.get("folder_exts",".hcl,.txt,.policy"), key="folder_exts")
        st.button("Scan folder", key="btn_scan_folder", on_click=lambda: st.session_state.update(do_scan=True))

    st.subheader("Filter")
    st.selectbox("Severity", ["all", "high", "low", "syntax", "risky"], index=0, key="severity")

# ---- Main page ----
st.title("Vault Policy Permission Checker (HCL Policy Format)")
st.caption("Paste or upload a policy, set a request path & capability, and view results here.")

left, right = st.columns([2, 1])
with left:
    st.text_input("Request Path", value=st.session_state.request_path, key="request_path_main")
with right:
    st.selectbox("Operation / Capability", CAPABILITIES, index=CAPABILITIES.index(st.session_state.operation), key="operation_main")

if st.session_state.mode == "Single file":
    if st.session_state.source == "Paste text":
        st.text_area("Policy (paste here)", value=st.session_state.policy_text, height=320, key="policy_text_input")
        st.button("Check Policy", key="btn_check_policy", on_click=lambda: st.session_state.update(check_policy_clicked=True))
        if st.session_state.check_policy_clicked:
            _compute_and_store(st.session_state.policy_text_input)
            st.session_state.check_policy_clicked = False
    else:
        if st.session_state.load_clicked:
            uf = st.session_state.get("uploaded_policy")
            if uf is None:
                st.warning("No file selected. Choose a file in the sidebar, then click **Load File**.")
            else:
                file_text = uf.getvalue().decode("utf-8", errors="replace")
                _compute_and_store(file_text)
            st.session_state.load_clicked = False

    _show_stats_sidebar(st.session_state.stats, "Single file")

    st.subheader("Results")
    if st.session_state.hcl_errors:
        st.error("HCL Syntax Error(s):")
        for m in filter_by_severity(st.session_state.hcl_errors, st.session_state.severity):
            st.write(f"- {m}")

    if st.session_state.rules:
        with st.expander("Parsed Rules"):
            for r in st.session_state.rules[:1000]:
                st.code(f'path "{r.get("path","")}" -> caps: {sorted(r.get("capabilities", []))}')

        if st.session_state.overlaps:
            st.warning("Overlapping ACL paths detected:")
            for p, rs in st.session_state.overlaps.items():
                st.write(f"- `{p}` appears in {len(rs)} rules")
            for s in suggest_optimizations(st.session_state.overlaps):
                st.info(f"- {s}")

        for m in filter_by_severity(st.session_state.risky_msgs, st.session_state.severity):
            (st.error if "[high]" in m.lower() else st.warning)(m)

        if st.button("Check Permission for Path", key="btn_check_perm"):
            policies = [{"name": "inline", "rules": st.session_state.rules}]
            matches, all_caps = check_policies(
                policies,
                st.session_state.get("request_path_main") or st.session_state.request_path,
                st.session_state.get("operation_main") or st.session_state.operation,
            )
            if not matches:
                st.error("No matching rules found for this path.")
            else:
                if "deny" in all_caps:
                    st.error("Permission DENIED due to explicit `deny` on the highest-priority match.")
                elif (st.session_state.get("operation_main") or st.session_state.operation) in all_caps:
                    st.success("Permission GRANTED by the highest-priority match.")
                else:
                    st.warning("Operation not explicitly granted by the highest-priority match.")
                with st.expander("Matched rules (by priority)"):
                    for _, r in matches:
                        st.write(f"- `{r['path']}` → caps: {sorted(r.get('capabilities', []))}")

else:
    total_files = total_policies = total_syntax = 0
    total_overlaps: Dict[str, Any] = {}
    total_risk = {"high": 0, "low": 0, "risky": 0}

    if st.session_state.get("do_scan"):
        folder = st.session_state.get("folder_path", "")
        exts = st.session_state.get("folder_exts", ".hcl,.txt,.policy")
        st.session_state.do_scan = False

        if not folder.strip():
            st.warning("Enter a folder path in the sidebar, then press **Scan folder**.")
        else:
            folder_path = Path(folder)
            if not folder_path.exists() or not folder_path.is_dir():
                st.error("Folder not found or not a directory.")
            else:
                include_exts = {e.strip().lower() for e in exts.split(",") if e.strip()}
                files: List[Path] = []
                for root, _, filenames in os.walk(folder_path):
                    for fn in filenames:
                        p = Path(root) / fn
                        if p.suffix.lower() in include_exts:
                            files.append(p)

                total_files = len(files)
                st.subheader(f"Scan Results — {total_files} file(s)")

                for file_path in files:
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                    except Exception as e:
                        st.error(f"Syntax: Error reading {file_path}: {e}")
                        continue

                    hcl_errs = hcl_syntax_check(text)
                    rules = parse_vault_policy(text) if not hcl_errs else []
                    ovs = find_overlapping_acls(rules) if rules else {}
                    risks = risky_grants_lint(rules) if rules else []

                    total_policies += len(rules)
                    total_syntax += len(hcl_errs)
                    for k, v in ovs.items():
                        total_overlaps.setdefault(k, []).extend(v)
                    rc = risk_counts(risks)
                    for k in ("high", "low", "risky"):
                        total_risk[k] += rc[k]

                    with st.expander(f"{file_path}"):
                        if hcl_errs:
                            st.error("Syntax Errors:")
                            for m in filter_by_severity(hcl_errs, st.session_state.severity):
                                st.write(f"- {m}")
                        if rules:
                            st.markdown("**Rules:**")
                            for r in rules[:300]:
                                st.code(f'path "{r.get("path","")}" -> caps: {sorted(r.get("capabilities", []))}')
                            if ovs:
                                st.warning("Overlaps:")
                                for p, rs in ovs.items():
                                    st.write(f"- `{p}` appears in {len(rs)} rules")
                                for s in suggest_optimizations(ovs):
                                    st.info(f"- {s}")
                            for m in filter_by_severity(risks, st.session_state.severity):
                                (st.error if "[high]" in m.lower() else st.warning)(m)

    folder_stats = {"files": total_files, "policies": total_policies, "syntax": total_syntax,
                    "overlaps": len(total_overlaps), **total_risk}
    _show_stats_sidebar(folder_stats, "Scan folder")

st.caption("Note: Only `capabilities` are checked; attributes like `control_group` are ignored for now.")