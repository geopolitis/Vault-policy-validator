import pytest
from main import (
    hcl_syntax_check,
    parse_vault_policy,
    check_policies,
    VALID_CAPS
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
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/data/myapp/config",
        "read"
    )
    assert "read" in all_caps

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
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/data/myapp/config",
        "read"
    )
    assert "deny" in all_caps
    assert "read" in all_caps

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
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "prod/secret/data/foo/bar",
        "update"
    )
    assert "update" in all_caps
    assert "read" not in all_caps

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
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "prod/secret/data/foo/bar",
        "read"
    )
    assert "update" in all_caps
    assert "read" not in all_caps

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
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/foo/config",
        "read"
    )
    assert "read" in all_caps
    # Does NOT match two segments
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/foo/bar/config",
        "read"
    )
    assert all_caps == set()

def test_star_at_end_matches_prefix():
    policy_text = '''
    path "secret/foo*" {
      capabilities = ["read"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/foobar",
        "read"
    )
    assert "read" in all_caps

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
    rules1 = parse_vault_policy(policy1)
    rules2 = parse_vault_policy(policy2)
    matches, all_caps = check_policies(
        [
            {"name": "p1", "rules": rules1},
            {"name": "p2", "rules": rules2}
        ],
        "secret/data/foo",
        "update"
    )
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
    rules1 = parse_vault_policy(policy_text1)
    rules2 = parse_vault_policy(policy_text2)
    matches, all_caps = check_policies(
        [
            {"name": "p1", "rules": rules1},
            {"name": "p2", "rules": rules2}
        ],
        "secret/data/foo",
        "read"
    )
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
    # Both have same length, wildcard count, etc., so lexicographic decides
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/data/fop",
        "update"
    )
    assert "update" in all_caps

def test_no_match_returns_empty():
    policy_text = '''
    path "secret/data/foo" {
      capabilities = ["read"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/data/bar",
        "read"
    )
    assert matches == []
    assert all_caps == set()

def test_complex_priority_from_vault_docs():
    policy_text = '''
    path "secret/*" {
      capabilities = ["read"]
    }
    path "secret/+/+/foo/*" {
      capabilities = ["update"]
    }
    '''
    rules = parse_vault_policy(policy_text)
    matches, all_caps = check_policies(
        [{"name": "inline", "rules": rules}],
        "secret/a/b/foo/config",
        "update"
    )
    # Second path has more + segments => lower priority, so read should win
    assert "read" in all_caps
    assert "update" not in all_caps
