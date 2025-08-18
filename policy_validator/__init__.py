from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Set

@dataclass(frozen=True)
class Rule:
    path: str
    capabilities: Set[str]
    source: str
    lineno: int

@dataclass(frozen=True)
class Finding:
    severity: Literal["high", "risky", "low"]
    code: str
    message: str
    path: str | None = None
    source: str | None = None
    lineno: int | None = None

@dataclass(frozen=True)
class Stats:
    files: int = 0
    policies: int = 0
    syntax: int = 0
    overlaps: int = 0
    high: int = 0
    low: int = 0
    risky: int = 0
