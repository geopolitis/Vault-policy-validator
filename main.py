import streamlit as st
import re
import ast
import fnmatch
from collections import defaultdict

# ---- Capability catalogue ----
CAPABILITIES = [
    # Standard, roughly mapping to HTTP verbs
    "create",  # POST/PUT
    "read",    # GET
    "update",  # POST/PUT
    "patch",   # PATCH
    "delete",  # DELETE
    "list",    # LIST
    # Non-HTTP-mapped
    "sudo",
    "deny",
    "subscribe",
    "recover",
]
VALID_CAPS = set(CAPABILITIES)

st.title("Vault Policy Permission Checker (HCL Policy Format)")

st.markdown("""
Paste your Vault policy blocks below. This tool validates HCL-like blocks and checks if
a requested capability is granted on a path using simple Vault-like priority rules.

**Supported capabilities**

- `create` : Create data at the path. Most operations require both `create` and `update`.
- `read` : Read data at the path.
- `update` : Change data at the path (often implies create when value is missing).
- `patch` : Partial updates for a path.
- `delete` : Delete data at the path.
- `list` : List keys/values at a path (keys are not policy-filtered).
- `sudo`: Access root-protected paths (must be combined with other required caps like read/delete).
- `deny`: Explicitly disallow access (takes precedence over all others, including sudo).
- `subscribe`: Subscribe to events for the path.
- `recover`: Recover data for the path from a snapshot.
""")

request_path = st.text_input("Request Path", value="")
operation = st.selectbox(
    "Operation / Capability to Check",
    CAPABILITIES
)
st.markdown("**Vault Policy (HCL format)**")
policy_text = st.text_area(
    "Paste Vault policy blocks here",
    value="",
    height=400
)

PATH_BLOCK_RE = re.compile(r'path\s+"([^"]+)"\s*\{([^}]+)\}', re.DOTALL)
CAPS_RE = re.compile(r'capabilities\s*=\s*\[([^\]]+)\]')

def parse_cap_list(src: str, path: str):
    """Parse capabilities list and validate against allowed list."""
    try:
        capabilities = ast.literal_eval(f'[{src}]')
        if not isinstance(capabilities, list):
            return None, f'Capabilities list syntax error in path "{path}": Must be inside square brackets.'

        caps = []
        for c in capabilities:
            if not isinstance(c, str):
                return None, (
                    f'Capabilities list syntax error in path "{path}": '
                    'Must be a comma-separated list of quoted strings, e.g. ["read", "list"]'
                )
            caps.append(c.strip())

        # Unknown capability names
        unknown = [c for c in caps if c not in VALID_CAPS]
        if unknown:
            if len(unknown) == 1:
                return None, (
                    f'Unknown capability "{unknown[0]}" in path "{path}". '
                    f"Allowed: {', '.join(sorted(VALID_CAPS))}"
                )
            else:
                return None, (
                    f'Unknown capabilities {unknown} in path "{path}". '
                    f"Allowed: {', '.join(sorted(VALID_CAPS))}"
                )

        return caps, None

    except (SyntaxError, ValueError):
        # Try to guess tokens even if syntax is broken
        possible_tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', src)
        guessed_unknowns = [tok for tok in possible_tokens if tok not in VALID_CAPS]
        if guessed_unknowns:
            return None, (
                f'Capabilities list syntax error in path "{path}": Invalid or unquoted capabilities '
                f'{guessed_unknowns}. Must be quoted strings, e.g. ["read", "list"].'
            )
        else:
            return None, (
                f'Capabilities list syntax error in path "{path}": '
                'Must be a comma-separated list of quoted strings, e.g. ["read", "list"]'
            )

def hcl_syntax_check(policy_text: str):
    errors = []
    if policy_text.count('"') % 2 != 0:
        errors.append('Unmatched double quote (").')
    if policy_text.count('{') != policy_text.count('}'):
        errors.append("Unmatched curly brace ({ or }).")

    path_blocks = PATH_BLOCK_RE.findall(policy_text)
    if not path_blocks:
        errors.append("No valid 'path' blocks found.")
        return errors

    for path, block in path_blocks:
        caps_match = CAPS_RE.search(block)
        if not caps_match:
            errors.append(f"Missing or malformed 'capabilities' in block for path: {path}")
            continue
        # NOTE: now pass the path
        _, parse_err = parse_cap_list(caps_match.group(1), path)
        if parse_err:
            errors.append(parse_err)

    return errors

def parse_vault_policy(policy_text: str):
    """Return list of rules: [{path: str, capabilities: [str]}]."""
    rules = []
    for path, block in PATH_BLOCK_RE.findall(policy_text):
        m = CAPS_RE.search(block)
        if not m:
            continue
        # NOTE: now pass the path
        caps_list, parse_err = parse_cap_list(m.group(1), path)
        if parse_err:
            # skip malformed rules; the syntax checker already reports details
            continue
        rules.append({"path": path.strip(), "capabilities": caps_list})
    return rules


def match_path(policy_path: str, request_path: str) -> bool:
    """Use fnmatch semantics ('*' and '?') to approximate Vault pattern matching."""
    return fnmatch.fnmatch(request_path, policy_path)

def policy_path_priority(path: str):
    """Sort priority: earlier wildcard beats later (inf means none), then endswith '*',
    then number of '+' segments (to allow experimenting), then path length (longer preferred),
    then path lexicographically for stability."""
    first_wildcard = min([i for i in (path.find('*'), path.find('?')) if i != -1] or [float('inf')])
    ends_with_star = path.endswith('*')
    plus_segments = path.split('/').count('+')
    path_len = len(path)
    return (first_wildcard, ends_with_star, plus_segments, path_len, path)

def check_policies(policies, request_path: str, operation: str):
    matching = []
    for policy in policies:
        for rule in policy['rules']:
            if match_path(rule['path'], request_path):
                matching.append((policy['name'], rule))
    if not matching:
        return [], set()
    matching.sort(key=lambda x: policy_path_priority(x[1]['path']))
    best_priority = policy_path_priority(matching[0][1]['path'])
    best_matches = [m for m in matching if policy_path_priority(m[1]['path']) == best_priority]
    all_caps = set()
    for _, rule in best_matches:
        all_caps.update(rule['capabilities'])
    return best_matches, all_caps

# ---- UI logic ----
hcl_errors = hcl_syntax_check(policy_text)
if hcl_errors:
    st.error("HCL Syntax Error(s) detected:")
    for err in hcl_errors:
        st.write(f"- {err}")

policies = [{"name": "inline", "rules": parse_vault_policy(policy_text)}]

if st.button("Check Permission"):
    if hcl_errors:
        st.warning("Please fix HCL syntax errors before checking permissions.")
    else:
        matches, all_caps = check_policies(policies, request_path, operation)

        if "deny" in all_caps:
            st.error("Permission DENIED due to explicit 'deny' capability on the highest-priority match.")
        elif operation in all_caps:
            st.success("Permission GRANTED by the following policy/rule(s):")
            for name, rule in matches:
                st.write(f"- {rule['path']} with capabilities {rule['capabilities']}")
            st.write(f"**Effective capabilities:** {sorted(all_caps)}")
        else:
            st.error("Permission DENIED: No policy grants this capability on the path.")
            if matches:
                st.info(f"Effective capabilities at this priority: {sorted(all_caps)}")

# ---- Overlap detection ----
def find_overlapping_acls(rules):
    path_map = defaultdict(list)
    for rule in rules:
        norm_path = rule['path'].replace('*', '')
        path_map[norm_path].append(rule)
    overlaps = {p: r for p, r in path_map.items() if len(r) > 1}
    return overlaps

def suggest_optimizations(overlaps):
    suggestions = []
    for path, rules in overlaps.items():
        all_caps = set()
        for rule in rules:
            all_caps.update(rule['capabilities'])
        if len(rules) > 1:
            suggestions.append(
                f"For path '{path}' found {len(rules)} ACLs. "
                f"Consider merging into one with capabilities: {sorted(all_caps)}."
            )
    return suggestions

rules = parse_vault_policy(policy_text)
overlaps = find_overlapping_acls(rules)
if overlaps:
    st.warning("Overlapping ACLs detected for the following paths:")
    for path, ruleset in overlaps.items():
        st.write(f"- {path} appears in {len(ruleset)} rules:")
        for rule in ruleset:
            st.write(f"    - Capabilities: {rule['capabilities']}")
    suggestions = suggest_optimizations(overlaps)
    if suggestions:
        st.info("**Optimization Suggestions:**")
        for s in suggestions:
            st.write(f"- {s}")
else:
    if policy_text.strip():
        st.success("No overlapping ACLs detected. Your policy is optimized.")

st.caption("Note: Only 'capabilities' are checked; attributes like 'control_group' are ignored for now.")
