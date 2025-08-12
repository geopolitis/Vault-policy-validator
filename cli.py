#!/usr/bin/env python3
import argparse
import json
from parser import hcl_syntax_check, parse_vault_policy, CAPABILITIES
from priority import check_policies
from lints import find_overlapping_acls, suggest_optimizations, risky_grants_lint

def main():
    parser = argparse.ArgumentParser(
        description="Validate Vault HCL policies and check capabilities"
    )
    parser.add_argument("--file", "-f", required=True, help="Path to policy file (.hcl-like)")
    parser.add_argument("--path", "-p", required=True, help="Request path to check")
    parser.add_argument("--cap", "-c", required=True, choices=CAPABILITIES, help="Capability to check")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    with open(args.file, "r") as f:
        policy_text = f.read()

    # Step 1: Syntax validation
    hcl_errors = hcl_syntax_check(policy_text)
    if hcl_errors:
        if args.json:
            print(json.dumps({"errors": hcl_errors}, indent=2))
        else:
            print("HCL Syntax Error(s) detected:")
            for err in hcl_errors:
                print(f"- {err}")
        exit(1)

    # Step 2: Parse policies
    rules = parse_vault_policy(policy_text)
    policies = [{"name": args.file, "rules": rules}]

    # Step 3: Capability check
    matches, all_caps = check_policies(policies, args.path, args.cap)

    # Step 4: Output results
    result = {
        "request_path": args.path,
        "capability": args.cap,
        "matches": matches,
        "effective_caps": sorted(all_caps),
        "decision": "granted" if args.cap in all_caps and "deny" not in all_caps else "denied",
        "deny_present": "deny" in all_caps
    }

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

    # Step 5: Lints
    overlaps = find_overlapping_acls(rules)
    risky = risky_grants_lint(rules)
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

if __name__ == "__main__":
    main()
