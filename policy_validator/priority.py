from __future__ import annotations
from typing import List, Set, Literal, Tuple
from . import Rule
from . import matcher

Decision = Literal["ALLOW", "DENY", "NOT_MATCHED"]

def _best_cohort(rules: List[Rule], req_path: str) -> List[Rule]:
    matches = [r for r in rules if matcher.match_path(r.path, req_path)]
    if not matches:
        return []
    best = max((matcher.specificity_tuple(r.path) for r in matches))
    return [r for r in matches if matcher.specificity_tuple(r.path) == best]

def decide(rules: List[Rule], req_path: str, capability: str) -> Decision:
    cohort = _best_cohort(rules, req_path)
    if not cohort:
        return "NOT_MATCHED"
    # union caps on best cohort; deny wins
    caps: Set[str] = set()
    for r in cohort:
        caps.update(r.capabilities)
    if "deny" in caps:
        return "DENY"
    return "ALLOW" if capability in caps else "NOT_MATCHED"

# Convenience: return cohort + union caps (used by UI/CLI for display)
def cohort_and_caps(rules: List[Rule], req_path: str) -> Tuple[List[Rule], Set[str]]:
    cohort = _best_cohort(rules, req_path)
    caps: Set[str] = set()
    for r in cohort:
        caps |= r.capabilities
    return cohort, caps
