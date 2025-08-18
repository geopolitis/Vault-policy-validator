from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Set, Tuple
from . import Rule

# Strict capability catalog
CAPABILITIES: List[str] = [
    "create", "read", "update", "patch", "delete",
    "list", "sudo", "deny", "subscribe", "revoke",
]
VALID_CAPS: Set[str] = set(CAPABILITIES)

# Regex for both syntaxes:
#   path "pattern" { ... }
#   path("pattern") { ... }
_PATH_BLOCKS = re.compile(
    r'(?P<full>path\s*(?:\(\s*"(?P<pat1>[^"]+)"\s*\)|"(?P<pat2>[^"]+)")\s*\{(?P<body>.*?)\})',
    re.DOTALL | re.IGNORECASE
)
_CAPS = re.compile(r'\bcapabilities\b\s*=\s*(\[[^\]]*\]|"[^"]+"|\w+)', re.DOTALL | re.IGNORECASE)
# any k = v pairs inside body for unknown key warnings
_KEY_ASSIGN = re.compile(r'^\s*([A-Za-z_]\w*)\s*=', re.MULTILINE)

def _lineno(src: str, start_idx: int) -> int:
    return src.count("\n", 0, start_idx) + 1

def _strip_inline_comments(src: str) -> str:
    # We only ignore full-line comments via lints; inline are kept for simplicity
    return src

def _barewords_inside_list(list_text: str) -> List[str]:
    inner = list_text.strip()[1:-1]  # remove [ ]
    # Remove quoted strings, then find identifiers
    inner_no_quotes = re.sub(r'"[^"]*"', "", inner)
    return re.findall(r'[A-Za-z_][A-Za-z0-9_]*', inner_no_quotes)

def hcl_syntax_check(text: str) -> List[str]:
    """
    Validate structure & capability tokens. Returns list of error/warning messages.
    Never raises; callers may still proceed to parse.
    """
    text = _strip_inline_comments(text or "")
    msgs: List[str] = []

    if text.count("{") != text.count("}"):
        msgs.append("Unmatched curly brace ({ or }).")
    if text.count("[") != text.count("]"):
        msgs.append("Unmatched bracket ([ or ]).")
    if text.count('"') % 2 != 0:
        msgs.append('Unmatched double quote (").')

    # Unknown keys + capabilities validation per block
    for m in _PATH_BLOCKS.finditer(text):
        body = m.group("body")
        path = m.group("pat1") or m.group("pat2") or ""

        # '*' anywhere except as suffix is likely a mistake
        if "*" in path and not path.endswith("*"):
            msgs.append(f'Invalid glob in path "{path}": "*" is only allowed as the final character.')

        # unknown keys (warning)
        for km in _KEY_ASSIGN.finditer(body):
            key = km.group(1)
            if key.lower() != "capabilities":
                msgs.append(f"[low] Unknown key '{key}' in block for path '{path}'.")

        caps_m = _CAPS.search(body)
        if not caps_m:
            msgs.append(f"Missing or malformed 'capabilities' in block for path: '{path}'")
            continue

        raw = caps_m.group(1).strip()
        if raw.startswith("[") and raw.endswith("]"):
            bare = _barewords_inside_list(raw)
            if bare:
                msgs.append(
                    f"Capabilities list syntax error in path '{path}': Invalid or unquoted capabilities {bare}. "
                    "Must be quoted strings, e.g. [\"read\", \"list\"]."
                )
                # continue validating values; parser will still try to read quoted caps

        # Now validate values (quoted list, single quoted, or bareword)
        caps_list: List[str]
        if raw.startswith("[") and raw.endswith("]"):
            caps_list = re.findall(r'"([^"]+)"', raw)
        elif raw.startswith('"') and raw.endswith('"'):
            caps_list = [raw[1:-1]]
        else:
            caps_list = [raw]  # bareword

        unknown = [c for c in caps_list if c not in VALID_CAPS]
        if unknown:
            if len(unknown) == 1:
                msgs.append(f"Unknown capability '{unknown[0]}' in path '{path}'. Allowed: {', '.join(sorted(VALID_CAPS))}")
            else:
                msgs.append(f"Unknown capabilities {unknown} in path '{path}'. Allowed: {', '.join(sorted(VALID_CAPS))}")

    # [low] commented-out rules detector
    for i, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            if 'path "' in line or "capabilities" in line:
                msgs.append("[low] Commented-out rules detected (lines starting with #). Consider removing them.")
                break  # only one low message needed

    return msgs

def parse_vault_policy(text: str, source: str = "inline") -> List[Rule]:
    """
    Best-effort extraction of rules. Invalid blocks are skipped.
    """
    text = text or ""
    rules: List[Rule] = []
    for m in _PATH_BLOCKS.finditer(text):
        full, body = m.group("full"), m.group("body")
        path = m.group("pat1") or m.group("pat2") or ""
        line = _lineno(text, m.start())

        # Skip paths with mid-string star (invalid per policy)
        if "*" in path and not path.endswith("*"):
            continue

        caps_m = _CAPS.search(body)
        if not caps_m:
            continue
        raw = caps_m.group(1).strip()
        if raw.startswith("[") and raw.endswith("]"):
            caps_list = re.findall(r'"([^"]+)"', raw)
        elif raw.startswith('"') and raw.endswith('"'):
            caps_list = [raw[1:-1]]
        else:
            caps_list = [raw]  # bareword

        # validate capabilities; skip invalids
        caps_set = {c for c in caps_list if c in VALID_CAPS}
        if not caps_set:
            continue

        rules.append(Rule(path=path.strip(), capabilities=caps_set, source=source, lineno=line))

    return rules
