from __future__ import annotations
from typing import List, Tuple

def _split(s: str) -> List[str]:
    return [seg for seg in s.strip("/").split("/") if seg != ""]

def _seg_matches(pseg: str, rseg: str) -> bool:
    """Match a single segment with support for '+', and trailing '*' within the segment."""
    if pseg == "+":  # exactly one segment of anything
        return True
    if pseg.endswith("*"):
        # Only allow trailing '*' wildcard at end of the segment (prefix match)
        return rseg.startswith(pseg[:-1])
    # literal match
    return pseg == rseg

def match_path(pattern: str, request_path: str) -> bool:
    """
    Path matching with Vault-like semantics:
      - '+' matches exactly one path segment
      - a standalone final segment '*' (e.g., '.../*') matches any suffix (0+ segments)
      - a trailing '*' inside the last segment (e.g., '.../foo*') is a prefix match for that segment
    """
    p_segs, r_segs = _split(pattern), _split(request_path)

    # Case 1: pattern ends with a standalone segment '*': suffix match with flexible tail length
    if p_segs and p_segs[-1] == "*":
        fixed = p_segs[:-1]
        if len(r_segs) < len(fixed):  # '*' can match zero or more segments
            return False
        # All fixed segments (before '*') must match segment-by-segment
        for i, pseg in enumerate(fixed):
            if not _seg_matches(pseg, r_segs[i]):
                return False
        return True

    # Case 2: no standalone '*' at the end -> lengths must match exactly
    if len(p_segs) != len(r_segs):
        return False

    # Compare each segment
    for pseg, rseg in zip(p_segs, r_segs):
        if not _seg_matches(pseg, rseg):
            return False
    return True

def specificity_tuple(pattern: str) -> Tuple[int, int, int]:
    """
    Specificity ordering:
      1) number of non-wildcard segments (higher is better)
      2) total number of segments       (higher is better)
      3) negative wildcard count        (fewer wildcards is better)
    """
    segs = _split(pattern)
    non_wild = 0
    wildcard_count = 0
    for s in segs:
        if s == "+" or s == "*":
            wildcard_count += 1
        elif s.endswith("*"):
            # trailing '*' inside a segment counts as a wildcard occurrence
            wildcard_count += 1
            non_wild += 1 if s[:-1] else 0
        else:
            non_wild += 1
    total = len(segs)
    return (non_wild, total, -wildcard_count)
