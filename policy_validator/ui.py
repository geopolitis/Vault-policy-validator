import streamlit as st
from parser import (
    CAPABILITIES, VALID_CAPS, hcl_syntax_check, parse_vault_policy
)
from priority import check_policies
from lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint

st.title("Vault Policy Permission Checker (HCL Policy Format)")

st.markdown("""
Paste your Vault policy blocks below. This tool validates HCL-like blocks and checks if
a requested capability is granted on a path using Vault's documented priority rules.

**Supported capabilities**:
""" + "\n".join(f"- `{cap}`" for cap in CAPABILITIES))

request_path = st.text_input("Request Path", value="")
operation = st.selectbox("Operation / Capability to Check", CAPABILITIES)
st.markdown("**Vault Policy (HCL format)**")
policy_text = st.text_area("Paste Vault policy blocks here", value="", height=400)

# ---- Validate & parse ----
hcl_errors = hcl_syntax_check(policy_text)
if hcl_errors:
    st.error("HCL Syntax Error(s) detected:")
    for err in hcl_errors:
        st.write(f"- {err}")

rules = parse_vault_policy(policy_text)
policies = [{"name": "inline", "rules": rules}]

# ---- Check permission ----
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

            # Show which rule(s) won
            for name, rule in matches:
                st.write(f"- Pattern: `{rule['path']}` from policy `{name}` with capabilities {rule['capabilities']}")
            st.write(f"**Effective capabilities:** {sorted(all_caps)}")

# ---- Lints / Overlaps ----
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

if policy_text.strip() and not hcl_errors and not overlaps:
    st.success("No overlapping ACLs detected. Your policy is optimized.")

st.caption("Note: Only 'capabilities' are checked; attributes like 'control_group' are ignored for now.")
