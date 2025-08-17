from __future__ import annotations
from typing import List, Dict, Any, Tuple, Set
import streamlit as st

try:
    from policy_validator.parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import check_policies
    from utils import find_overlapping_acls, suggest_optimizations, risky_grants_lint
except ModuleNotFoundError:
    from ..parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from ..priority import check_policies
    from ..utils import find_overlapping_acls, suggest_optimizations, risky_grants_lint

import importlib.metadata
version = importlib.metadata.version("policy_validator")

def _render_errors(errors: List[str]) -> None:
    if errors:
        st.error("HCL Syntax Error(s) detected:")
        for err in errors:
            st.write(f"- {err}")

def filter_by_severity(messages, severity):
    if severity == "all":
        return messages
    if severity == "syntax":
        return [m for m in messages if "Syntax" in m or "syntax" in m]
    if severity == "high":
        return [m for m in messages if "[HIGH]" in m]
    if severity == "low":
        return [m for m in messages if "[low]" in m]
    if severity == "risky":
        return [m for m in messages if "Risky" in m or "risky" in m or "Wildcard path" in m]
    return messages

def get_risk_counts(risky: list[str]) -> dict:
    return {
        "high": len([m for m in risky if "[HIGH]" in m]),
        "low": len([m for m in risky if "[low]" in m]),
        "risky": len([m for m in risky if "risky" in m.lower() or "wildcard path" in m.lower()]),
    }

def show_statistics_sidebar(stats: dict, mode: str):
    if mode == "Single file":
        st.sidebar.markdown("### File Statistics")
    else:
        st.sidebar.markdown("### Folder Scan Statistics")

    st.sidebar.write(f"- Files searched: {stats.get('files', 0)}")
    st.sidebar.write(f"- Policies parsed: {stats.get('policies', 0)}")
    st.sidebar.write(f"- Syntax errors: {stats.get('syntax', 0)}")
    st.sidebar.write(f"- Overlapping ACL paths: {stats.get('overlaps', 0)}")
    st.sidebar.write(f"- High risk findings: {stats.get('high', 0)}")
    st.sidebar.write(f"- Low risk findings: {stats.get('low', 0)}")
    st.sidebar.write(f"- Risky findings: {stats.get('risky', 0)}")

def main() -> None:
    st.title("Vault Policy Permission Checker (HCL Policy Format)")

    # Sidebar: mode, severity, file/folder selection
    st.sidebar.header("Options")
    mode = st.sidebar.radio("Mode", ["Single file", "Scan folder"])
    severity = st.sidebar.selectbox("Filter by severity", ["all", "high", "low", "syntax", "risky"], index=0,
                                    help="Show only messages of the selected severity")

    uploaded_file = None
    folder_path = ""

    if mode == "Single file":
        uploaded_file = st.sidebar.file_uploader("Upload a policy file (.hcl)", type=["hcl"])
    else:
        try:
            folder = st.sidebar.directory_uploader("Select a folder to scan", key="folder_scan")
            if folder:
                folder_path = folder.name if hasattr(folder, "name") else ""
        except Exception:
            folder_path = st.sidebar.text_input("Folder to scan (absolute or relative path)")

    st.markdown("**Supported capabilities:** " + ", ".join(f"`{cap}`" for cap in CAPABILITIES))
    request_path = st.text_input("Request Path", value="/")
    operation = st.selectbox("Operation / Capability to Check", CAPABILITIES)

    # Policy text area
    policy_text = ""
    if uploaded_file is not None:
        uploaded_content = uploaded_file.read().decode("utf-8")
        policy_text = st.text_area("Paste policy block here", value=uploaded_content, height=400)
    else:
        policy_text = st.text_area("Paste Vault policy blocks here", value="", height=400)

    if mode == "Single file":
        hcl_errors: List[str] = hcl_syntax_check(policy_text)
        _render_errors(filter_by_severity(hcl_errors, severity))

        rules: List[Dict[str, Any]] = parse_vault_policy(policy_text)
        policies: List[Dict[str, Any]] = [{"name": "inline", "rules": rules}]

        if st.button("Check Permission"):
            if hcl_errors:
                st.warning("Please fix HCL syntax errors before checking permissions.")
            else:
                matches, all_caps = check_policies(policies, request_path, operation)
                if not matches:
                    st.error("No matching rules found for this path.")
                else:
                    if "deny" in all_caps:
                        st.error("Permission DENIED due to explicit 'deny' capability on the highest-priority match.")
                    elif operation in all_caps:
                        st.success("Permission GRANTED by the highest-priority pattern:")
                    else:
                        st.error("Permission DENIED: No policy grants this capability on the path.")
                    st.info(f"Effective capabilities at this priority: {sorted(all_caps)}")

                    for name, rule in matches:
                        st.write(f"- Pattern: `{rule['path']}` from policy `{name}` with capabilities `{rule['capabilities']}`")

        # Show filtered overlaps and risky grants
        messages = []
        overlaps = find_overlapping_acls(rules)
        risky = risky_grants_lint(rules)

        if overlaps:
            messages.append("Overlapping ACLs detected for the following paths:")
            for path, ruleset in overlaps.items():
                messages.append(f"- `{path}` appears in {len(ruleset)} rules:")
                for rule in ruleset:
                    messages.append(f"   - Capabilities: {rule['capabilities']}")
            for s in suggest_optimizations(overlaps):
                messages.append(f"- {s}")

        messages.extend(risky)

        for msg in filter_by_severity(messages, severity):
            st.warning(msg)

        if policy_text.strip() and not hcl_errors and not overlaps:
            st.success("No overlapping ACLs detected. Your policy is optimized.")

        # Show statistics in the sidebar for single file
        risk_counts = get_risk_counts(risky)
        stats = {
            "policies": len(rules),
            "syntax": len(hcl_errors),
            "overlaps": len(overlaps),
            **risk_counts,
        }
        show_statistics_sidebar(stats, mode="Single file")

    else:  # Scan folder mode
        if st.button("Scan Folder", disabled=not folder_path):
            import os
            files = []
            total_policies = 0
            total_overlaps = set()
            total_syntax = 0
            total_risk = {"high": 0, "low": 0, "risky": 0}
            for root, _, fs in os.walk(folder_path):
                for f in fs:
                    if f.lower().endswith(".hcl"):
                        files.append(os.path.join(root, f))

            if not files:
                st.warning("No .hcl files found in the folder.")
            else:
                for file_path in files:
                    st.write(f"**Validating:** `{file_path}`")
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            policy_text = f.read()
                    except Exception as e:
                        st.error(f"Error reading {file_path}: {e}")
                        continue

                    hcl_errors = hcl_syntax_check(policy_text)
                    rules = parse_vault_policy(policy_text)
                    total_policies += len(rules)
                    overlaps = find_overlapping_acls(rules)
                    total_overlaps.update(overlaps.keys())
                    risky = risky_grants_lint(rules)
                    rc = get_risk_counts(risky)

                    total_syntax += len([m for m in hcl_errors if "syntax" in m.lower()])
                    total_risk["high"] += rc["high"]
                    total_risk["low"] += rc["low"]
                    total_risk["risky"] += rc["risky"]

                    messages = []
                    if hcl_errors:
                        messages.extend(hcl_errors)
                    if overlaps:
                        messages.append("Overlapping ACLs detected for the following paths:")
                        for path, ruleset in overlaps.items():
                            messages.append(f"- `{path}` appears in {len(ruleset)} rules:")
                            for rule in ruleset:
                                messages.append(f"   - Capabilities: {rule['capabilities']}")
                        for s in suggest_optimizations(overlaps):
                            messages.append(f"- {s}")
                    messages.extend(risky)

                    for msg in filter_by_severity(messages, severity):
                        st.warning(msg)

                    if policy_text.strip() and not hcl_errors and not overlaps:
                        st.success("No overlapping ACLs detected. Your policy is optimized.")

                # Show statistics in the sidebar for folder scan
                stats = {
                    "files": len(files),
                    "policies": total_policies,
                    "syntax": total_syntax,
                    "overlaps": len(total_overlaps),
                    **total_risk,
                }
                show_statistics_sidebar(stats, mode="Scan folder")

    st.caption("Note: Only `capabilities` are checked; attributes like `control_group` are ignored for now.")
    st.caption(f"Version: `{version}`")

if __name__ == "__main__":
    main()
