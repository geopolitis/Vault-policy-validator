from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Set, Tuple

from . import Rule, Finding, Stats

# Configurable set of high-risk capabilities
HIGH_RISK = {"delete", "sudo", "update", "patch", "revoke"}

def lint_overlaps(rules: Iterable[Rule]) -> List[Finding]:
    """Same literal path appears in multiple rules (possibly different caps)."""
    by_path: Dict[str, List[Rule]] = defaultdict(list)
    for r in rules:
        by_path[r.path].append(r)
    findings: List[Finding] = []
    for path, rs in by_path.items():
        if len(rs) > 1:
            findings.append(
                Finding(
                    severity="low",
                    code="OVERLAP",
                    message=f"{path} appears in {len(rs)} rules. Suggestion: merge rules for path {path}.",
                    path=path,
                    source=None,
                    lineno=None,
                )
            )
    return findings

def lint_risky(rules: Iterable[Rule]) -> List[Finding]:
    """Wildcard + high-risk capability."""
    findings: List[Finding] = []
    for r in rules:
        has_wild = r.path.endswith("*") or "/+/" in f"/{r.path}/" or r.path.startswith("+/") or r.path.startswith("*/")
        risky_caps = sorted(HIGH_RISK.intersection(r.capabilities))
        if has_wild and risky_caps:
            cap_code = "WILDCARD_" + ("_".join(c.upper() for c in risky_caps) if len(risky_caps) == 1 else "HIGH_CAP")
            findings.append(
                Finding(
                    severity="high",
                    code=cap_code,
                    message=f"Wildcard path '{r.path}' grants high-risk capabilities {risky_caps}.",
                    path=r.path,
                    source=r.source,
                    lineno=r.lineno,
                )
            )
    return findings

def lint_commented_rules(text_by_source: Dict[str, str]) -> List[Finding]:
    """Lines starting with # that contain a plausible rule/capabilities."""
    findings: List[Finding] = []
    for src, text in text_by_source.items():
        for i, line in enumerate((text or "").splitlines(), start=1):
            s = line.lstrip()
            if s.startswith("#") and ('path "' in s or "capabilities" in s):
                findings.append(
                    Finding(
                        severity="low",
                        code="COMMENTED_RULE",
                        message="[low] Commented-out rules detected (lines starting with #). Consider removing them.",
                        path=None,
                        source=src,
                        lineno=i,
                    )
                )
                break  # one per file is enough
    return findings

def aggregate_stats(
    findings: Iterable[Finding],
    files: int,
    policies: int,
    syntax_errors: int,
    overlaps_count: int | None = None
) -> Stats:
    high = low = risky = 0
    overlap_seen = overlaps_count if overlaps_count is not None else 0
    for f in findings:
        if f.code == "OVERLAP":
            overlap_seen += 1
        if f.severity == "high":
            high += 1
        elif f.severity == "low":
            low += 1
        else:
            risky += 1
    return Stats(
        files=files, policies=policies, syntax=syntax_errors,
        overlaps=overlap_seen, high=high, low=low, risky=risky
    )
