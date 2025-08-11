import pytest
from main import (
    parse_cap_list,
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
    assert errors == []  # No syntax errors
    rules = parse_vault_policy(policy_text)
    assert rules[0]['capabilities'] == ["read", "list"]
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
    assert "read" in all_caps  # present, but deny should override in app logic

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
    errors = hcl_syntax_check(policy_text)
    assert errors == []
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
