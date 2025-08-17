from __future__ import annotations
from functools import cmp_to_key
from typing import List, Set, Tuple, Dict, Any, cast
from policy_validator import matcher

def _first_wildcard_pos(p: str) -> int:
    plus = p.find('+')
    star = p.find('*')
    positions = [i for i in (plus, star) if i != -1]
    return min(positions) if positions else 10**9

def compare_policy_paths(p1: str, p2: str) -> int:
    # 1) later first wildcard is higher priority
    fwl1, fwl2 = _first_wildcard_pos(p1), _first_wildcard_pos(p2)
    if fwl1 != fwl2:
        return -1 if fwl1 > fwl2 else 1
    # 2) not ending in * is higher priority
    e1, e2 = p1.endswith('*'), p2.endswith('*')
    if e1 != e2:
        return -1 if (not e1 and e2) else 1
    # 3) fewer '+' is higher priority
    c1, c2 = p1.split('/').count('+'), p2.split('/').count('+')
    if c1 != c2:
        return -1 if c1 < c2 else 1
    # 4) longer path is higher priority
    if len(p1) != len(p2):
        return -1 if len(p1) > len(p2) else 1
    # 5) lexicographically larger is higher priority
    if p1 != p2:
        return -1 if p1 > p2 else 1
    return 0
# NEW: typed comparator for (policy_name, rule_dict) tuples
def _cmp_match(
    a: Tuple[str, Dict[str, Any]],
    b: Tuple[str, Dict[str, Any]]
) -> int:
    pa = cast(str, a[1]['path'])
    pb = cast(str, b[1]['path'])
    return compare_policy_paths(pa, pb)

def check_policies(
    policies: List[Dict[str, Any]],
    request_path: str,
    operation: str
) -> Tuple[List[Tuple[str, Dict[str, Any]]], Set[str]]:

    matching: List[Tuple[str, Dict[str, Any]]] = []
    for policy in policies:
        name = cast(str, policy.get('name', 'inline'))
        rules = cast(List[Dict[str, Any]], policy.get('rules', []))
        for rule in rules:
            path = cast(str, rule.get('path', ''))
            if matcher.match_path(path, request_path):
                matching.append((name, rule))

    if not matching:
        return [], set()

    # Use the typed comparator
    matching.sort(key=cmp_to_key(_cmp_match))

    best_path = cast(str, matching[0][1]['path'])
    best_matches: List[Tuple[str, Dict[str, Any]]] = [
        m for m in matching if cast(str, m[1]['path']) == best_path
    ]

    all_caps: Set[str] = set()
    for _, rule in best_matches:
        for cap in cast(List[str], rule.get('capabilities', [])):
            all_caps.add(cap)

    return best_matches, all_caps

