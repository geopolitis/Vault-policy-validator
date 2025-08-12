from functools import cmp_to_key
from typing import List, Tuple, Set
import matcher

def _first_wildcard_pos(p: str) -> int:
    plus = p.find('+')
    star = p.find('*')
    positions = [i for i in (plus, star) if i != -1]
    return min(positions) if positions else 10**9  # large number == "no wildcard"

def compare_policy_paths(p1: str, p2: str) -> int:
    """
    Vault priority rules:
    1) If first wildcard occurs later in P1, P1 is higher priority
    2) If P1 ends with '*' and P2 doesn't, P1 is lower priority
    3) If P1 has more '+' segments, P1 is lower priority
    4) If P1 is shorter, it is lower priority
    5) If P1 is smaller lexicographically, it is lower priority
    Return -1 if p1 higher priority, +1 if lower, 0 if equal.
    """
    fw1, fw2 = _first_wildcard_pos(p1), _first_wildcard_pos(p2)
    if fw1 != fw2:
        return -1 if fw1 > fw2 else 1

    e1, e2 = p1.endswith('*'), p2.endswith('*')
    if e1 != e2:
        return -1 if (not e1 and e2) else 1

    c1, c2 = p1.split('/').count('+'), p2.split('/').count('+')
    if c1 != c2:
        return -1 if c1 < c2 else 1

    if len(p1) != len(p2):
        return -1 if len(p1) > len(p2) else 1

    if p1 != p2:
        return -1 if p1 > p2 else 1

    return 0

def check_policies(policies, request_path: str, operation: str) -> Tuple[List[tuple], Set[str]]:
    """
    policies: [{"name": <str>, "rules": [{"path": <str>, "capabilities": [str]}]}]
    Returns: (best_matches, effective_caps)
    """
    matching = []
    for policy in policies:
        for rule in policy['rules']:
            if matcher.match_path(rule['path'], request_path):
                matching.append((policy['name'], rule))

    if not matching:
        return [], set()

    # Sort by priority (highest first) using comparator
    matching.sort(key=cmp_to_key(lambda a, b: compare_policy_paths(a[1]['path'], b[1]['path'])))
    best_path = matching[0][1]['path']

    # Union capabilities across SAME PATTERN from different policies
    best_matches = [m for m in matching if m[1]['path'] == best_path]
    all_caps = set()
    for _, rule in best_matches:
        all_caps.update(rule['capabilities'])

    return best_matches, all_caps
