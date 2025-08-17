# parser.py
from __future__ import annotations

import re
from typing import List, Optional, Tuple, Dict, Any, Set

# Allowed capabilities (extend as needed)
CAPABILITIES: List[str] = [
    "create", "read", "update", "patch", "delete",
    "list", "sudo", "deny", "subscribe", "recover",
]
VALID_CAPS: Set[str] = set(CAPABILITIES)

# Support BOTH syntaxes:
#   1) path("pattern") { ... }
#   2) path "pattern" { ... }
PATH_BLOCK_PAREN_RE = re.compile(r'path\s*\(\s*"([^"]+)"\s*\)\s*\{(.*?)\}', re.DOTALL)
PATH_BLOCK_LABEL_RE = re.compile(r'path\s*"([^"]+)"\s*\{(.*?)\}', re.DOTALL)

# Capabilities can be:
#   - list:    capabilities = ["read", "list"]
#   - string:  capabilities = "read"
#   - bareword capabilities = read
CAPS_RE = re.compile(r'\bcapabilities\b\s*=\s*(\[[^\]]*\]|"[^"]+"|\w+)', re.DOTALL)

def _normalize_caps_value(raw: str, path: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Convert the raw capabilities value (matched as a string) into a validated list[str].
    Supports list syntax, quoted string, or bareword.
    """
    raw = raw.strip()

    # Parse list of quoted strings: ["read","list"]
    if raw.startswith("[") and raw.endswith("]"):
        # Extract quoted items robustly (avoid naive split on commas)
        items = re.findall(r'"([^"]+)"', raw)
        caps_list = [i.strip() for i in items]
    # Parse single quoted string: "read"
    elif raw.startswith('"') and raw.endswith('"'):
        caps_list = [raw[1:-1].strip()]
    else:
        # bareword: read
        caps_list = [raw]

    # Validate names
    unknown = [c for c in caps_list if c not in VALID_CAPS]
    if unknown:
        if len(unknown) == 1:
            return None, (
                f"Unknown capability '{unknown[0]}' in path '{path}'. "
                f"Allowed: {', '.join(sorted(VALID_CAPS))}"
            )
        return None, (
            f"Unknown capabilities {unknown} in path '{path}'. "
            f"Allowed: {', '.join(sorted(VALID_CAPS))}"
        )

    return caps_list, None

def preprocess_policy(policy_text: str) -> Tuple[str, bool]:
    """Strip full-line comments that start with '#' and report if any were removed."""
    lines = policy_text.splitlines()
    had_comments = False
    filtered: List[str] = []
    for line in lines:
        if re.match(r'^\s*#', line):
            had_comments = True
            continue
        filtered.append(line)
    return "\n".join(filtered), had_comments

def hcl_syntax_check(policy_text: str) -> List[str]:
    """
    Lightweight structural validation + capability validation hints.
    Returns a list of error/warning messages (strings).
    """
    errors: List[str] = []

    # Preprocess to remove commented-out lines
    policy_text, had_comments = preprocess_policy(policy_text)
    if had_comments:
        errors.append("[low] Commented-out rules detected (lines starting with #). Consider removing them.")

    # Very lightweight structural checks (heuristics; keep them gentle)
    if policy_text.count('"') % 2 != 0:
        errors.append('Unmatched double quote (").')
    if policy_text.count('{') != policy_text.count('}'):
        errors.append("Unmatched curly brace ({ or }).")

    # Find path blocks in BOTH syntaxes
    path_blocks = []
    path_blocks += PATH_BLOCK_PAREN_RE.findall(policy_text)
    path_blocks += PATH_BLOCK_LABEL_RE.findall(policy_text)

    if not path_blocks:
        errors.append("No valid 'path' blocks found.")
        return errors

    # Validate each block
    for path, block in path_blocks:
        # Optional sanity check about glob placement (adjust to your rules)
        if "*" in path and not path.endswith("*"):
            errors.append(f"Invalid glob in path '{path}': '*' is only allowed as the final character.")

        caps_match = CAPS_RE.search(block)
        if not caps_match:
            errors.append(f"Missing or malformed 'capabilities' in block for path: '{path}'")
            continue

        _, parse_err = _normalize_caps_value(caps_match.group(1), path)
        if parse_err:
            errors.append(parse_err)

    return errors

def parse_vault_policy(policy_text: str) -> List[Dict[str, Any]]:
    """Return list of rules: [{'path': str, 'capabilities': List[str]}]."""
    # Remove commented-out lines before parsing
    policy_text, _ = preprocess_policy(policy_text)

    # Collect BOTH syntaxes
    all_blocks = []
    all_blocks += PATH_BLOCK_PAREN_RE.findall(policy_text)
    all_blocks += PATH_BLOCK_LABEL_RE.findall(policy_text)

    rules: List[Dict[str, Any]] = []
    for path, block in all_blocks:
        m = CAPS_RE.search(block)
        if not m:
            continue
        caps_list, parse_err = _normalize_caps_value(m.group(1), path)
        if parse_err:
            # Skip invalid rule; syntax checker already reports the issue
            continue
        rules.append({"path": path.strip(), "capabilities": caps_list})

    return rules
