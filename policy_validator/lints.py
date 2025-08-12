from collections import defaultdict
from typing import Dict, List

def find_overlapping_acls(rules: List[dict]) -> Dict[str, List[dict]]:
    path_map: Dict[str, List[dict]] = defaultdict(list)
    for rule in rules:
        norm_path = rule['path'].replace('*', '')
        path_map[norm_path].append(rule)
    return {p: r for p, r in path_map.items() if len(r) > 1}

def suggest_optimizations(overlaps: Dict[str, List[dict]]) -> List[str]:
    suggestions: List[str] = []
    for path, rules in overlaps.items():
        all_caps = set()
        for rule in rules:
            all_caps.update(rule['capabilities'])
        suggestions.append(
            f"For path '{path}' found {len(rules)} ACLs. "
            f"Consider merging into one with capabilities: {sorted(all_caps)}."
        )
    return suggestions

def risky_grants_lint(rules: List[dict]) -> List[str]:
    warnings: List[str] = []
    risky = {"delete", "sudo", "recover"}
    for r in rules:
        if r['path'] in ("*", "/*", "secret/*") or r['path'].endswith("*"):
            bad = sorted(risky.intersection(r['capabilities']))
            if bad:
                warnings.append(
                    f"Broad pattern '{r['path']}' grants high-risk capabilities {bad}. "
                    "Consider narrowing the path."
                )
    return warnings
