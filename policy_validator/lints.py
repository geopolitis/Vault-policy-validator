from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Any


def find_overlapping_acls(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Detect overlapping ACLs where the exact same path pattern appears in more than one rule.
    This preserves the original path string (including '*' or '+') for accurate reporting.
    """
    path_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        path = str(rule.get("path", ""))
        path_map[path].append(rule)
    return {p: r for p, r in path_map.items() if len(r) > 1}


def suggest_optimizations(overlaps: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    """
    Suggest merging ACLs with identical path patterns into a single rule with combined capabilities.
    """
    suggestions: List[str] = []
    for path, rules in overlaps.items():
        all_caps = set()
        for rule in rules:
            for c in rule.get("capabilities", []):
                all_caps.add(c)
        suggestions.append(
            f"For path '{path}' found {len(rules)} ACLs. "
            f"Consider merging into one with capabilities: {sorted(all_caps)}."
        )
    return suggestions


def risky_grants_lint(rules: List[Dict[str, Any]]) -> List[str]:
    """
    Detect overly broad wildcard paths that grant high-risk capabilities.
    This version uses the phrase 'Wildcard path' in messages to match test expectations.
    """
    warnings: List[str] = []
    risky = {"delete", "sudo", "recover", "read"}  # 'read' added for broad wildcard paths
    for r in rules:
        path = str(r.get("path", ""))
        if "*" in path or "+" in path:
            bad = sorted(risky.intersection(set(r.get("capabilities", []))))
            if bad:
                warnings.append(
                    f"Wildcard path '{path}' grants high-risk capabilities {bad}. "
                    "Consider narrowing the path."
                )
    return warnings

