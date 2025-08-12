import re
import ast
from typing import List, Optional, Tuple

CAPABILITIES: List[str] = [
    "create",   # POST/PUT
    "read",     # GET
    "update",   # POST/PUT
    "patch",    # PATCH
    "delete",   # DELETE
    "list",     # LIST
    "sudo",
    "deny",
    "subscribe",
    "recover",
]
VALID_CAPS: set[str] = set(CAPABILITIES)

PATH_BLOCK_RE = re.compile(r'path\s+"([^"]+)"\s*\{([^}]+)\}', re.DOTALL)
CAPS_RE = re.compile(r'capabilities\s*=\s*\[([^\]]+)\]')

def parse_cap_list(src: str, path: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Parse capabilities list and validate against allowed list."""
    try:
        capabilities = ast.literal_eval(f'[{src}]')
        if not isinstance(capabilities, list):
            return None, f'Capabilities list syntax error in path "{path}": Must be inside square brackets.'

        caps: List[str] = []
        for c in capabilities:
            if not isinstance(c, str):
                return None, (
                    f'Capabilities list syntax error in path "{path}": '
                    'Must be a comma-separated list of quoted strings, e.g. ["read", "list"]'
                )
            caps.append(c.strip())

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

def hcl_syntax_check(policy_text: str) -> List[str]:
    """Lightweight HCL-like validation and capability validation."""
    errors: List[str] = []
    if policy_text.count('"') % 2 != 0:
        errors.append('Unmatched double quote (").')
    if policy_text.count('{') != policy_text.count('}'):
        errors.append("Unmatched curly brace ({ or }).")

    path_blocks = PATH_BLOCK_RE.findall(policy_text)
    if not path_blocks:
        errors.append("No valid 'path' blocks found.")
        return errors

    for path, block in path_blocks:
        if '*' in path and not path.endswith('*'):
            errors.append(f'Invalid glob in path "{path}": "*" is only allowed as the final character.')
        caps_match = CAPS_RE.search(block)
        if not caps_match:
            errors.append(f"Missing or malformed 'capabilities' in block for path: {path}")
            continue
        _, parse_err = parse_cap_list(caps_match.group(1), path)
        if parse_err:
            errors.append(parse_err)

    return errors

def parse_vault_policy(policy_text: str) -> List[dict]:
    """Return list of rules: [{path: str, capabilities: [str]}]."""
    rules: List[dict] = []
    for path, block in PATH_BLOCK_RE.findall(policy_text):
        m = CAPS_RE.search(block)
        if not m:
            continue
        caps_list, parse_err = parse_cap_list(m.group(1), path)
        if parse_err:
            continue
        rules.append({"path": path.strip(), "capabilities": caps_list})
    return rules
