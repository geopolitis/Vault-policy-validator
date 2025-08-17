from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Any

def find_overlapping_acls(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Return mapping of path -> list of rules that share the same path."""
    path_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rules:
        path = str(r.get("path", ""))
        path_map[path].append(r)
    return {p: rs for p, rs in path_map.items() if len(rs) > 1}

def suggest_optimizations(overlaps: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    tips: List[str] = []
    for path, rs in overlaps.items():
        caps_sets = [tuple(sorted(set(r.get("capabilities", [])))) for r in rs]
        if len(set(caps_sets)) == 1:
            tips.append(f"Merge {len(rs)} identical rules for `{path}` into a single block.")
    return tips

def risky_grants_lint(rules: List[Dict[str, Any]]) -> List[str]:
    warnings: List[str] = []
    risky = {"create", "update", "patch", "delete", "sudo"}
    for r in rules:
        path = str(r.get("path", ""))
        caps = set(r.get("capabilities", []))

        if "sudo" in caps:
            warnings.append(f"[high] `sudo` granted on `{path}`")

        if path.startswith("+/") or path.startswith("*/"):
            warnings.append(
                f"[high] Path '{path}' starts with a broad wildcard (+/ or */). "
                "This is extremely risky. Consider restricting the path."
            )

        if ("*" in path) or ("+" in path):
            bad = sorted(risky.intersection(caps))
            if bad:
                warnings.append(
                    f"[high] wildcard path '{path}' grants high-risk capabilities {bad}. "
                    "Consider narrowing the path."
                )
            elif caps == {"read"}:
                warnings.append(f"[low] read-only wildcard on `{path}`")
    return warnings

# Centralized tiny helpers used by UI/CLI
def risk_counts(messages: List[str]) -> Dict[str, int]:
    lower = [m.lower() for m in messages]
    return {
        "high": sum("[high]" in m for m in lower),
        "low": sum("[low]" in m for m in lower),
        "risky": sum(("risky" in m) or ("wildcard" in m) for m in lower),
    }

def filter_by_severity(messages: List[str], severity: str) -> List[str]:
    s = (severity or "all").lower()
    if s == "all": return messages
    if s == "syntax": return [m for m in messages if "syntax" in m.lower()]
    if s == "high": return [m for m in messages if "[high]" in m.lower()]
    if s == "low": return [m for m in messages if "[low]" in m.lower()]
    if s == "risky": return [m for m in messages if "risky" in m.lower() or "wildcard" in m.lower()]
    return messages
