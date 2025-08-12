import re

def match_path(policy_path: str, request_path: str) -> bool:
    """
    Vault-like match:
    - '+' matches exactly one non-slash segment
    - '*' is a glob only if it is the final character: prefix match
    - Any other '*' usage is invalid and treated as non-match (the parser should already flag it)
    """
    rx = re.escape(policy_path)
    rx = rx.replace(r'\+', r'[^/]+')
    if rx.endswith(r'\*'):
        rx = rx[:-2] + r'.*'
    elif r'\*' in rx:
        return False
    return re.fullmatch(rx, request_path) is not None
