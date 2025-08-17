from __future__ import annotations
from typing import List, Dict, Any
import streamlit as st

# Prefer package imports; fall back to local modules when running from repo root
try:
    from policy_validator.parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import check_policies
    from policy_validator.lints import (
        find_overlapping_acls, suggest_optimizations, risky_grants_lint,
        risk_counts, filter_by_severity,
    )
except Exception:
    from parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy  # type: ignore
    from priority import check_policies  # type: ignore
    from lints import (  # type: ignore
        find_overlapping_acls, suggest_optimizations, risky_grants_lint,
        risk_counts, filter_by_severity,
    )

st.set_page_config(page_title="Vault Policy Checker", layout="wide", initial_sidebar_state="expanded")

st.sidebar.title("Vault Policy Checker")
mode = st.sidebar.radio("Mode", ["Single file", "Scan folder"])
severity = st.sidebar.selectbox("Filter by severity", ["all", "high", "low", "syntax", "risky"], index=0)

# Request
request_path = st.sidebar.text_input("Request Path (e.g., secret/data/foo/bar)", value="")
operation = st.sidebar.selectbox("Operation / Capability", CAPABILITIES)

if mode == "Single file":
    use_paste = st.sidebar.checkbox("Paste text instead of uploading", value=True)
    if use_paste:
        policy_text = st.text_area("Paste Vault policy blocks here", value="", height=320)
        check_clicked = st.button("Check Policy")
        if check_clicked:
            hcl_errors = hcl_syntax_check(policy_text) if policy_text.strip() else []
            rules = parse_vault_policy(policy_text) if not hcl_errors else []
            overlaps = find_overlapping_acls(rules) if rules else {}
            risky_msgs = risky_grants_lint(rules) if rules else []
    else:
        uploaded = st.sidebar.file_uploader("Upload policy (.hcl, .txt)", type=["hcl", "txt"])
        loaded = st.sidebar.button("Load File")
        policy_text = uploaded.read().decode("utf-8", errors="replace") if (uploaded and loaded) else ""
        hcl_errors = hcl_syntax_check(policy_text) if policy_text.strip() else []
        rules = parse_vault_policy(policy_text) if not hcl_errors else []
        overlaps = find_overlapping_acls(rules) if rules else {}
        risky_msgs = risky_grants_lint(rules) if rules else []

    stats = {
        "files": 1 if (policy_text.strip()) else 0,
        "policies": len(rules) if 'rules' in locals() else 0,
        "syntax": len(hcl_errors) if 'hcl_errors' in locals() else 0,
        "overlaps": len(overlaps) if 'overlaps' in locals() else 0,
        **(risk_counts(risky_msgs) if 'risky_msgs' in locals() else {"high":0,"low":0,"risky":0}),
    }
    with st.sidebar:
        st.markdown("### Statistics")
        st.write(f"- Files searched: {stats.get('files', 0)}")
        st.write(f"- Policies parsed: {stats.get('policies', 0)}")
        st.write(f"- Syntax errors: {stats.get('syntax', 0)}")
        st.write(f"- Overlapping ACL paths: {stats.get('overlaps', 0)}")
        st.write(f"- High risk findings: {stats.get('high', 0)}")
        st.write(f"- Low risk findings: {stats.get('low', 0)}")
        st.write(f"- Risky findings: {stats.get('risky', 0)}")

    st.subheader("Results")
    if 'hcl_errors' in locals() and hcl_errors:
        st.error("HCL Syntax Error(s):")
        for m in filter_by_severity(hcl_errors, severity):
            st.write(f"- {m}")

    if 'rules' in locals() and rules:
        if overlaps:
            st.warning("Overlapping ACL paths detected:")
            for p, rs in overlaps.items():
                st.write(f"- `{p}` appears in {len(rs)} rules")
            for s in suggest_optimizations(overlaps):
                st.info(f"- {s}")
        for m in filter_by_severity(risky_msgs, severity):
            (st.error if "[high]" in m.lower() else st.warning)(m)

        if st.button("Check Permission"):
            matches, all_caps = check_policies([{"name": "inline", "rules": rules}], request_path, operation)
            if not matches:
                st.error("No matching rules found for this path.")
            else:
                if "deny" in all_caps:
                    st.error("Permission DENIED due to explicit `deny` on the highest-priority match.")
                elif operation in all_caps:
                    st.success("Permission GRANTED by the highest-priority match.")
                else:
                    st.warning("Operation not explicitly granted by the highest-priority match.")
                with st.expander("Matched rules (by priority)"):
                    for _, r in matches:
                        st.write(f"- `{r['path']}` → caps: {sorted(r.get('capabilities', []))}")

else:
    from pathlib import Path
    import os
    folder = st.sidebar.text_input("Folder path (server-side)", value="")
    exts = st.sidebar.text_input("Include extensions (comma-separated)", value=".hcl,.txt,.policy")
    do_scan = st.sidebar.button("Scan folder")

    total_files = total_policies = total_syntax = 0
    total_overlaps: Dict[str, Any] = {}
    total_risk = {"high":0,"low":0,"risky":0}

    if do_scan and folder.strip():
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
            for fp in files:
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    st.error(f"Syntax: Error reading {fp}: {e}")
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
                for k in ("high","low","risky"):
                    total_risk[k] += rc[k]

                with st.expander(f"{fp}"):
                    if hcl_errs:
                        st.error("Syntax Errors:")
                        for m in filter_by_severity(hcl_errs, severity):
                            st.write(f"- {m}")
                    if rules:
                        if ovs:
                            st.warning("Overlaps:")
                            for pth, rs in ovs.items():
                                st.write(f"- `{pth}` appears in {len(rs)} rules")
                            for s in suggest_optimizations(ovs):
                                st.info(f"- {s}")
                        for m in filter_by_severity(risks, severity):
                            (st.error if "[high]" in m.lower() else st.warning)(m)

    stats = {"files": total_files, "policies": total_policies, "syntax": total_syntax,
             "overlaps": len(total_overlaps), **total_risk}
    with st.sidebar:
        st.markdown("### Statistics")
        st.write(f"- Files searched: {stats.get('files', 0)}")
        st.write(f"- Policies parsed: {stats.get('policies', 0)}")
        st.write(f"- Syntax errors: {stats.get('syntax', 0)}")
        st.write(f"- Overlapping ACL paths: {stats.get('overlaps', 0)}")
        st.write(f"- High risk findings: {stats.get('high', 0)}")
        st.write(f"- Low risk findings: {stats.get('low', 0)}")
        st.write(f"- Risky findings: {stats.get('risky', 0)}")
