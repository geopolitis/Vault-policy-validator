from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Any

def find_overlapping_acls(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect overlapping ACLs where the exact same path pattern appears in more than one rule.
    Preserves the original path string (including '*' or '+') for accurate reporting.
    """
    path_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rules:
        path = str(r.get("path", ""))
        path_map[path].append(r)
    return {p: rs for p, rs in path_map.items() if len(rs) > 1}

def suggest_optimizations(overlaps: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    """
    Suggest merging ACLs with identical path patterns into a single rule with combined capabilities.
    """
    suggestions: List[str] = []
    for path, rules in overlaps.items():
        all_caps = set()
        for r in rules:
            for c in r.get("capabilities", []):
                all_caps.add(c)
        suggestions.append(
            f"For path '{path}' found {len(rules)} ACLs. "
            f"Consider merging into one with capabilities: {sorted(all_caps)}."
        )
    return suggestions

def risky_grants_lint(rules: List[Dict[str, Any]]) -> List[str]:
    """
    Detect overly broad wildcard paths that grant high-risk capabilities.
    Adds a high-risk warning for paths starting with '+/', '*/' or similar.
    Also flags any wildcard path ('*' or '+') that grants risky capabilities.
    """
    warnings: List[str] = []
    # Capabilities considered risky in combination with wildcards
    risky = {"delete", "sudo", "recover", "read"}  # 'read' included for very broad wildcards
    for r in rules:
        path = str(r.get("path", ""))
        # High-risk: path starts with +/ or */ (very broad first segment wildcard)
        if path.startswith("+/") or path.startswith("*/"):
            warnings.append(
                f"[HIGH] Path '{path}' starts with a broad wildcard (+/ or */). This is extremely risky. "
                "Consider restricting the path."
            )
        # Existing wildcard risk detection
        if ("*" in path) or ("+" in path):
            bad = sorted(risky.intersection(set(r.get("capabilities", []))))
            if bad:
                warnings.append(
                    f"[HIGH] wildcard path '{path}' grants high-risk capabilities {bad}. "
                    "Consider narrowing the path."
                )
    return warnings
