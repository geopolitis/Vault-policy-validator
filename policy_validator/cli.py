from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Tuple

from policy_validator.parser import hcl_syntax_check, parse_vault_policy, CAPABILITIES
from policy_validator.priority import check_policies
from policy_validator.lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate Vault HCL policies and check capabilities"
    )
    parser.add_argument("--file", "-f", required=True, help="Path to policy file (.hcl-like)")
    parser.add_argument("--path", "-p", required=True, help="Request path to check")
    parser.add_argument("--cap", "-c", required=True, choices=CAPABILITIES, help="Capability to check")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            policy_text: str = f.read()
    except OSError as e:
        print(f"Error reading policy file: {e}", file=sys.stderr)
        return 2

    # 1) Syntax validation
    hcl_errors: List[str] = hcl_syntax_check(policy_text)
    if hcl_errors:
        if args.json:
            print(json.dumps({"errors": hcl_errors}, indent=2))
        else:
            print("HCL Syntax Error(s) detected:")
            for err in hcl_errors:
                print(f"- {err}")
        return 1

    # 2) Parse policies
    rules: List[Dict[str, Any]] = parse_vault_policy(policy_text)
    policies: List[Dict[str, Any]] = [{"name": args.file, "rules": rules}]

    # 3) Capability check
    matches, all_caps = check_policies(policies, args.path, args.cap)

    # 4) Result object
    decision: str = "granted" if (args.cap in all_caps and "deny" not in all_caps) else "denied"
    result: Dict[str, Any] = {
        "request_path": args.path,
        "capability": args.cap,
        "matches": matches,  # list of (policy_name, rule_dict)
        "effective_caps": sorted(all_caps),
        "decision": decision,
        "deny_present": "deny" in all_caps,
    }

    # 5) Output
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if not matches:
            print("No matching rules found for this path.")
        else:
            if "deny" in all_caps:
                print("Permission DENIED due to explicit 'deny' capability on the highest-priority match.")
            elif args.cap in all_caps:
                print("Permission GRANTED by the highest-priority pattern.")
            else:
                print("Permission DENIED: No policy grants this capability on the path.")
                print(f"Effective capabilities at this priority: {sorted(all_caps)}")

            print("\nMatched rules:")
            for name, rule in matches:
                print(f"- Pattern: {rule['path']} from policy {name} with capabilities {rule['capabilities']}")
            print(f"\nEffective capabilities: {sorted(all_caps)}")

        overlaps: Dict[str, List[Dict[str, Any]]] = find_overlapping_acls(rules)
        risky: List[str] = risky_grants_lint(rules)
        if overlaps:
            print("\nOverlapping ACLs detected:")
            for path, ruleset in overlaps.items():
                print(f"- {path} appears in {len(ruleset)} rules")
                for rule in ruleset:
                    print(f"    - Capabilities: {rule['capabilities']}")
            for s in suggest_optimizations(overlaps):
                print(f"Suggestion: {s}")

        if risky:
            print("\nRisky grants detected:")
            for r in risky:
                print(f"- {r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
