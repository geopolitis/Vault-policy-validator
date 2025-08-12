from __future__ import annotations
from typing import List, Dict, Any, Tuple, Set
import streamlit as st

try:
    # when installed as a package or PYTHONPATH points to repo root
    from policy_validator.parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import check_policies
    from policy_validator.lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint
except ModuleNotFoundError:  # fallback when running as a module inside the package
    from .parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy
    from .priority import check_policies
    from .lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint


def _render_errors(errors: List[str]) -> None:
    if errors:
        st.error("HCL Syntax Error(s) detected:")
        for err in errors:
            st.write(f"- {err}")

def main() -> None:
    st.title("Vault Policy Permission Checker (HCL Policy Format)")
    st.markdown(
        "Paste your Vault policy blocks below. This tool validates HCL-like blocks and "
        "checks if a requested capability is granted on a path using Vault's documented priority rules."
    )
    st.markdown("**Supported capabilities**:\n" + "\n".join(f"- `{cap}`" for cap in CAPABILITIES))

    request_path: str = st.text_input("Request Path", value="")
    operation: str = st.selectbox("Operation / Capability to Check", CAPABILITIES)
    st.markdown("**Vault Policy (HCL format)**")
    policy_text: str = st.text_area("Paste Vault policy blocks here", value="", height=400)

    hcl_errors: List[str] = hcl_syntax_check(policy_text)
    _render_errors(hcl_errors)

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
                    st.write(f"- Pattern: `{rule['path']}` from policy `{name}` with capabilities {rule['capabilities']}")
                st.write(f"**Effective capabilities:** {sorted(all_caps)}")

    if rules:
        overlaps = find_overlapping_acls(rules)
        if overlaps:
            st.warning("Overlapping ACLs detected for the following paths:")
            for path, ruleset in overlaps.items():
                st.write(f"- {path} appears in {len(ruleset)} rules:")
                for rule in ruleset:
                    st.write(f"    - Capabilities: {rule['capabilities']}")
            for s in suggest_optimizations(overlaps):
                st.info(f"- {s}")

        for w in risky_grants_lint(rules):
            st.warning(w)

    if policy_text.strip() and not hcl_errors and not find_overlapping_acls(rules):
        st.success("No overlapping ACLs detected. Your policy is optimized.")

    st.caption("Note: Only 'capabilities' are checked; attributes like 'control_group' are ignored for now.")

if __name__ == "__main__":
    main()