from __future__ import annotations
import re

def match_path(policy_path: str, request_path: str) -> bool:
    """
    Vault-like path matching:
    - '+' matches exactly one non-slash segment
    - '*' is a trailing glob only (prefix match)
    """
    rx = re.escape(policy_path)
    rx = rx.replace(r'\+', r'[^/]+')
    if rx.endswith(r'\*'):
        rx = rx[:-2] + r'.*'
    elif r'\*' in rx:
        return False
    return re.fullmatch(rx, request_path) is not None
