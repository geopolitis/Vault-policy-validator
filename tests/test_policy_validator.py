from __future__ import annotations
import pytest

from policy_validator.parser import (
    parse_vault_policy,
    hcl_syntax_check,
    CAPABILITIES,
    VALID_CAPS,  # final location for the capability set
)
from policy_validator.priority import decide, cohort_and_caps
from policy_validator.lints import (
    lint_overlaps,
    lint_risky,
    lint_commented_rules,
    aggregate_stats,
)


def test_happy_path():
    policy_text = '''
    path "secret/data/myapp/*" {
      capabilities = ["read", "list"]
    }
    '''
    errors = hcl_syntax_check(policy_text)
    assert errors == []
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "secret/data/myapp/config")
    assert "read" in all_caps
    assert decide(rules, "secret/data/myapp/config", "read") == "ALLOW"


def test_unknown_capability():
    policy_text = '''
    path "secret/data/myapp/*" {
      capabilities = ["read", "DoNotDelete"]
    }
    '''
    errors = hcl_syntax_check(policy_text)
    assert any("Unknown capability" in e for e in errors)


def test_syntax_error_missing_quotes():
    policy_text = '''
    path "secret/data/myapp/*" {
      capabilities = [read, list]
    }
    '''
    errors = hcl_syntax_check(policy_text)
    assert any("Invalid or unquoted capabilities" in e or "syntax error" in e.lower() for e in errors)


def test_deny_precedence():
    policy_text = '''
    path "secret/data/myapp/*" {
      capabilities = ["read", "deny"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "secret/data/myapp/config")
    assert "deny" in all_caps and "read" in all_caps
    assert decide(rules, "secret/data/myapp/config", "read") == "DENY"


def test_all_valid_caps():
    policy_text = f'''
    path "secret/data/myapp/*" {{
      capabilities = [{", ".join(f'"{c}"' for c in VALID_CAPS)}]
    }}
    '''
    errors = hcl_syntax_check(policy_text)
    assert errors == []


def test_priority_explicit_vs_wildcard_plus_segments():
    policy_text = '''
    path "prod/secret/+/+/something/*" {
      capabilities = ["read"]
    }
    path "prod/secret/data/foo/bar" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "prod/secret/data/foo/bar")
    assert "update" in all_caps
    assert "read" not in all_caps
    assert decide(rules, "prod/secret/data/foo/bar", "update") == "ALLOW"


def test_priority_explicit_vs_simple_wildcard():
    policy_text = '''
    path "prod/secret/data/foo/*" {
      capabilities = ["read"]
    }
    path "prod/secret/data/foo/bar" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "prod/secret/data/foo/bar")
    assert "update" in all_caps
    assert "read" not in all_caps
    assert decide(rules, "prod/secret/data/foo/bar", "read") == "NOT_MATCHED"


def test_invalid_midstring_star():
    policy_text = '''
    path "secret/*/data" {
      capabilities = ["read"]
    }
    '''
    errors = hcl_syntax_check(policy_text)
    assert any('"*" is only allowed as the final character' in e for e in errors)


def test_plus_matches_one_segment():
    policy_text = '''
    path "secret/+/config" {
      capabilities = ["read"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    # Matches one segment
    cohort, all_caps = cohort_and_caps(rules, "secret/foo/config")
    assert "read" in all_caps
    # Does NOT match two segments
    cohort, all_caps = cohort_and_caps(rules, "secret/foo/bar/config")
    assert all_caps == set()
    assert decide(rules, "secret/foo/bar/config", "read") == "NOT_MATCHED"


def test_star_at_end_matches_prefix():
    policy_text = '''
    path "secret/foo*" {
      capabilities = ["read"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "secret/foobar")
    assert "read" in all_caps
    assert decide(rules, "secret/foobar", "read") == "ALLOW"


def test_union_capabilities_same_path():
    policy1 = '''
    path "secret/data/foo" {
      capabilities = ["read"]
    }
    '''
    policy2 = '''
    path "secret/data/foo" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy1) + parse_vault_policy(policy2)
    cohort, all_caps = cohort_and_caps(rules, "secret/data/foo")
    assert "read" in all_caps and "update" in all_caps


def test_multiple_highest_priority_union():
    policy_text1 = '''
    path "secret/data/foo" {
      capabilities = ["read"]
    }
    '''
    policy_text2 = '''
    path "secret/data/foo" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy_text1) + parse_vault_policy(policy_text2)
    cohort, all_caps = cohort_and_caps(rules, "secret/data/foo")
    assert "read" in all_caps and "update" in all_caps


def test_lexicographic_priority():
    policy_text = '''
    path "secret/data/foo" {
      capabilities = ["read"]
    }
    path "secret/data/fop" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "secret/data/fop")
    assert "update" in all_caps
    assert decide(rules, "secret/data/fop", "update") == "ALLOW"


def test_no_match_returns_empty():
    policy_text = '''
    path "secret/data/foo" {
      capabilities = ["read"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "secret/data/bar")
    assert cohort == []
    assert all_caps == set()
    assert decide(rules, "secret/data/bar", "read") == "NOT_MATCHED"


def test_complex_priority_from_spec():
    # Per spec: exact > '+' > '*', and specificity tuple (non-wild, total, -wildcards) decides.
    policy_text = '''
    path "secret/*" {
      capabilities = ["read"]
    }
    path "secret/+/+/foo/*" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    cohort, all_caps = cohort_and_caps(rules, "secret/a/b/foo/config")
    # The 'secret/+/+/foo/*' pattern is more specific -> wins
    assert "update" in all_caps and "read" not in all_caps
    assert decide(rules, "secret/a/b/foo/config", "update") == "ALLOW"


def test_findings_and_stats_summary():
    policy_text = '''
    path "secret/foo" { capabilities = ["read"] }
    path "secret/foo" { capabilities = ["update"] }
    # path "secret/*" { capabilities = ["delete"] }
    path "secret/*" { capabilities = ["delete"] }
    '''
    rules = parse_vault_policy(policy_text)
    findings = []
    findings += lint_overlaps(rules)
    findings += lint_risky(rules)
    findings += lint_commented_rules({"inline": policy_text})
    # syntax errors exclude [low]
    fatal_syntax = [e for e in hcl_syntax_check(policy_text) if not e.lower().startswith("[low]")]
    stats = aggregate_stats(findings, files=1, policies=len(rules), syntax_errors=len(fatal_syntax))

    assert stats.overlaps >= 1     # overlap detected
    assert stats.high >= 1         # wildcard + delete is high
    assert stats.low >= 1          # commented rule counted as low
    #assert stats.risky >= 1        # risky lint detected
    #assert stats.files == 1
    #assert stats.policies == len(rules)
    #assert stats.syntax == len(fatal_syntax)  # syntax errors counted
