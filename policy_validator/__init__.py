"""
policy_validator package

Tools for validating Vault HCL policies, checking capabilities,
and detecting risky or overlapping ACLs.
"""

from __future__ import annotations

# Re-export main public API
from .parser import CAPABILITIES, hcl_syntax_check, parse_vault_policy, VALID_CAPS
from .priority import check_policies
from .lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint


__all__ = [
    "CAPABILITIES",
    "VALID_CAPS",
    "hcl_syntax_check",
    "parse_vault_policy",
    "check_policies",
    "find_overlapping_acls",
    "suggest_optimizations",
    "risky_grants_lint",
]
