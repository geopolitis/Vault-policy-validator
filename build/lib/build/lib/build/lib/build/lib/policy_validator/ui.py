# ui.py
from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import os
import streamlit as st

# --- Import from package or local files ---
try:
    from policy_validator.parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import check_policies
    from policy_validator.lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint
except Exception:
    from parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy  # type: ignore
    from priority import check_policies  # type: ignore
    from lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint  # type: ignore

# --- Page config ---
st.set_page_config(
    page_title="Vault Policy Permission Checker",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ========= Sidebar helpers =========
def _risk_counts(risky_msgs: List[str]) -> Dict[str, int]:
    low = [m.lower() for m in risky_msgs]
    return {
        "high": sum("[high]" in m for m in low),
        "low": sum("[low]" in m for m in low),
        "risky": sum(("risky" in m) or ("wildcard" in m) for m in low),
    }

def show_statistics_sidebar(stats: Dict[str, int], mode_label: str) -> None:
    st.sidebar.markdown("### Statistics")
    st.sidebar.write(f"- Mode: {mode_label}")
    st.sidebar.write(f"- Files searched: {stats.get('files', 0)}")
    st.sidebar.write(f"- Policies parsed: {stats.get('policies', 0)}")
    st.sidebar.write(f"- Syntax errors: {stats.get('syntax', 0)}")
    st.sidebar.write(f"- Overlapping ACL paths: {stats.get('overlaps', 0)}")
    st.sidebar.write(f"- High risk findings: {stats.get('high', 0)}")
    st.sidebar.write(f"- Low risk findings: {stats.get('low', 0)}")
    st.sidebar.write(f"- Risky findings: {stats.get('risky', 0)}")

def filter_by_severity(messages: List[str], severity: str) -> List[str]:
    if severity == "all":
        return messages
    s = severity.lower()
    if s == "syntax":
        return [m for m in messages if "syntax" in m.lower()]
    if s == "high":
        return [m for m in messages if "[high]" in m.lower()]
    if s == "low":
        return [m for m in messages if "[low]" in m.lower()]
    if s == "risky":
        return [m for m in messages if "risky" in m.lower() or "wildcard" in m.lower()]
    return messages

# ========= Sidebar controls (ALL the functionality you wanted visible) =========
st.sidebar.title("Vault Policy Checker")
st.sidebar.info("Load a file or scan a folder, choose severity filtering, and run permission checks.")

mode = st.sidebar.radio("Mode", ["Single file", "Scan folder"], index=0)

severity = st.sidebar.selectbox(
    "Filter by severity",
    ["all", "high", "low", "syntax", "risky"],
    index=0,
    help="Filter visible messages by severity tag/type.",
)

# Request path & capability (moved to sidebar so all controls are in one place)
request_path = st.sidebar.text_input("Request Path (e.g., secret/data/foo/bar)", value="")
operation = st.sidebar.selectbox("Operation / Capability", CAPABILITIES)

# Single-file controls
use_paste = False
uploaded_file = None
pasted_text = ""

if mode == "Single file":
    use_paste = st.sidebar.checkbox("Paste text instead of uploading a file", value=False)
    if use_paste:
        st.sidebar.caption("Scroll to the main area to paste policy text.")
    else:
        uploaded_file = st.sidebar.file_uploader("Upload policy (.hcl, .txt)", type=["hcl", "txt"])

# Folder scan controls
folder = ""
exts = ""
do_scan = False
if mode == "Scan folder":
    folder = st.sidebar.text_input("Folder path to scan (server-side path)", value="")
    exts = st.sidebar.text_input("Include extensions (comma-separated)", value=".hcl,.txt,.policy")
    do_scan = st.sidebar.button("Scan folder")

# ========= Main Area =========
st.title("Vault Policy Permission Checker (HCL Policy Format)")
st.caption("Validates HCL-like blocks, flags risks/overlaps, and checks capability resolution.")

# ---------------- Single file mode ----------------
if mode == "Single file":
    if use_paste:
        policy_text = st.text_area("Paste Vault policy blocks here", value="", height=320)
    else:
        if uploaded_file is not None:
            policy_text = uploaded_file.read().decode("utf-8", errors="replace")
        else:
            policy_text = ""

    # Parse & lint
    hcl_errors: List[str] = hcl_syntax_check(policy_text) if policy_text.strip() else []
    rules: List[Dict[str, Any]] = parse_vault_policy(policy_text) if not hcl_errors else []
    overlaps = find_overlapping_acls(rules) if rules else {}
    risky_msgs = risky_grants_lint(rules) if rules else []

    # Sidebar stats
    stats = {
        "files": 1 if (policy_text.strip() or (uploaded_file is not None)) else 0,
        "policies": len(rules),
        "syntax": len(hcl_errors),
        "overlaps": len(overlaps),
        **_risk_counts(risky_msgs),
    }
    show_statistics_sidebar(stats, "Single file")

    # Render messages
    if hcl_errors:
        for m in filter_by_severity(hcl_errors, severity):
            st.error(m)

    if rules:
        if overlaps:
            st.warning("Overlapping ACLs detected for the following paths:")
            for path, ruleset in overlaps.items():
                st.write(f"- `{path}` appears in {len(ruleset)} rules:")
                for rule in ruleset:
                    st.write(f"   - Capabilities: {rule.get('capabilities')}")
            for s in suggest_optimizations(overlaps):
                st.info(f"- {s}")
        for m in filter_by_severity(risky_msgs, severity):
            if "[high]" in m.lower():
                st.error(m)
            else:
                st.warning(m)

        # Permission check
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
                    for name, r in matches:
                        st.write(f"- `{r['path']}` → caps: {sorted(r.get('capabilities', []))}")

# ---------------- Folder scan mode ----------------
else:
    total_files = 0
    total_policies = 0
    total_syntax = 0
    total_overlaps: Dict[str, Any] = {}
    total_risk = {"high": 0, "low": 0, "risky": 0}
    messages: List[str] = []

    if do_scan and folder.strip():
        folder_path = Path(folder)
        if not folder_path.exists() or not folder_path.is_dir():
            st.error("Folder not found or not a directory.")
        else:
            include_exts = {e.strip().lower() for e in exts.split(",") if e.strip()}

            files = []
            for root, _, filenames in os.walk(folder_path):
                for fn in filenames:
                    p = Path(root) / fn
                    if p.suffix.lower() in include_exts:
                        files.append(p)

            total_files = len(files)
            for file_path in files:
                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    messages.append(f"Syntax: Error reading {file_path}: {e}")
                    continue

                hcl_errs = hcl_syntax_check(text)
                rules = parse_vault_policy(text) if not hcl_errs else []
                ovs = find_overlapping_acls(rules) if rules else {}
                risks = risky_grants_lint(rules) if rules else []

                total_policies += len(rules)
                total_syntax += len(hcl_errs)
                for k, v in ovs.items():
                    total_overlaps.setdefault(k, []).extend(v)
                rc = _risk_counts(risks)
                for k in ("high", "low", "risky"):
                    total_risk[k] += rc[k]

                # Collect messages (filtered)
                messages.extend(filter_by_severity(hcl_errs, severity))
                if ovs:
                    messages.append("Overlapping ACLs detected for:")
                    for path, ruleset in ovs.items():
                        messages.append(f"- `{path}` appears in {len(ruleset)} rules")
                    for s in suggest_optimizations(ovs):
                        messages.append(f"- {s}")
                messages.extend(filter_by_severity(risks, severity))

    # Sidebar stats always visible (even before scan → zeros)
    stats = {
        "files": total_files,
        "policies": total_policies,
        "syntax": total_syntax,
        "overlaps": len(total_overlaps),
        **total_risk,
    }
    show_statistics_sidebar(stats, "Scan folder")

    # Render results
    if messages:
        st.subheader("Scan Results")
        for m in messages:
            if "syntax" in m.lower():
                st.error(m)
            elif m.lower().startswith("overlapping acls"):
                st.warning(m)
            elif "[high]" in m.lower():
                st.error(m)
            else:
                st.warning(m)

st.caption("Note: Only `capabilities` are checked; attributes like `control_group` are ignored for now.")
