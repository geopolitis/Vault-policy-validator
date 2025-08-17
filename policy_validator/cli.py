from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple

try:
    from policy_validator.parser import hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import check_policies
    from policy_validator.lints import (
        find_overlapping_acls, suggest_optimizations, risky_grants_lint,
        risk_counts, filter_by_severity,
    )
except Exception:
    from parser import hcl_syntax_check, parse_vault_policy  # type: ignore
    from priority import check_policies  # type: ignore
    from lints import (  # type: ignore
        find_overlapping_acls, suggest_optimizations, risky_grants_lint,
        risk_counts, filter_by_severity,
    )

def analyze_text(text: str, severity: str = "all") -> Dict[str, Any]:
    hcl_errors: List[str] = hcl_syntax_check(text) if text.strip() else []
    rules: List[Dict[str, Any]] = parse_vault_policy(text) if not hcl_errors else []
    overlaps = find_overlapping_acls(rules) if rules else {}
    risky_msgs = risky_grants_lint(rules) if rules else []
    stats = {
        "files": 1 if text.strip() else 0,
        "policies": len(rules),
        "syntax": len(hcl_errors),
        "overlaps": len(overlaps),
        **risk_counts(risky_msgs),
    }
    return {
        "rules": rules,
        "errors": filter_by_severity(hcl_errors, severity),
        "overlaps": overlaps,
        "risky": filter_by_severity(risky_msgs, severity),
        "stats": stats,
    }

def load_policies_from_folder(folder: Path, exts: str, severity: str):
    include_exts = {e.strip().lower() for e in exts.split(",") if e.strip()}
    policies: List[Dict[str, Any]] = []
    totals = {"files": 0, "policies": 0, "syntax": 0, "overlaps": 0, "high": 0, "low": 0, "risky": 0}
    per_file: List[Dict[str, Any]] = []

    files = [p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in include_exts]
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            res = {"file": str(fp), "rules": [], "errors": [f"Read error: {e}"], "overlaps": {}, "risky": [], "stats": {"files": 1, "policies": 0, "syntax": 1, "overlaps": 0, "high": 0, "low": 0, "risky": 0}}
            per_file.append(res)
            totals["files"] += 1
            totals["syntax"] += 1
            continue

        res = analyze_text(text, severity)
        res["file"] = str(fp)
        per_file.append(res)

        totals["files"] += 1
        totals["policies"] += res["stats"]["policies"]
        totals["syntax"] += res["stats"]["syntax"]
        totals["overlaps"] += res["stats"]["overlaps"]
        totals["high"] += res["stats"]["high"]
        totals["low"] += res["stats"]["low"]
        totals["risky"] += res["stats"]["risky"]

        if res["rules"]:
            policies.append({"name": fp.name, "rules": res["rules"]})

    return policies, totals, per_file

def run_permission_check(policies: List[Dict[str, Any]], req_path: str, capability: str, show_matches: bool = False) -> int:
    if not policies:
        print("No policies to evaluate.", file=sys.stderr)
        return 1
    if not req_path:
        print("Missing --check-path.", file=sys.stderr)
        return 1
    if not capability:
        print("Missing --cap.", file=sys.stderr)
        return 1

    matches, all_caps = check_policies(policies, req_path, capability)

    if not matches:
        print("No matching rules found for this path.")
        return 3

    if "deny" in all_caps:
        print("Permission: DENIED (explicit 'deny' present at highest-priority).")
        code = 2
    elif capability in all_caps:
        print("Permission: GRANTED.")
        code = 0
    else:
        print("Permission: NOT EXPLICITLY GRANTED.")
        code = 3

    if show_matches:
        print("\nMatched rules (by priority):")
        for name, r in matches:
            caps = sorted(r.get("capabilities", []))
            print(f"- {name}: path \"{r.get('path','')}\" -> {caps}")

    return code

def main():
    ap = argparse.ArgumentParser(description="Vault policy validator (CLI)")
    ap.add_argument("path", help="Policy file or folder")
    ap.add_argument("--severity", choices=["all","high","low","syntax","risky"], default="all")
    ap.add_argument("--exts", default=".hcl,.txt,.policy", help="Comma-separated extensions (folder mode)")
    ap.add_argument("--check-path", dest="check_path", default="", help="Path to evaluate (e.g., secret/data/foo/bar)")
    ap.add_argument("--cap", dest="capability", default="", help="Capability to evaluate (e.g., read)")
    ap.add_argument("--show-matches", action="store_true", help="Print the matched rules")
    ap.add_argument("--json", action="store_true", help="Print JSON output")
    args = ap.parse_args()

    target = Path(args.path)
    exit_code = 0

    if target.is_file():
        text = target.read_text(encoding="utf-8", errors="replace")
        res = analyze_text(text, args.severity)

        if args.json:
            payload = {
                "file": str(target),
                "stats": res["stats"],
                "errors": res["errors"],
                "overlaps": {k: len(v) for k, v in (res["overlaps"] or {}).items()},
                "risky": res["risky"],
            }
            if args.check_path and args.capability:
                pols = [{"name": target.name, "rules": res["rules"]}]
                matches, all_caps = check_policies(pols, args.check_path, args.capability)
                payload["permission_check"] = {
                    "path": args.check_path,
                    "capability": args.capability,
                    "granted": args.capability in all_caps and "deny" not in all_caps,
                    "denied": "deny" in all_caps,
                    "matched_count": len(matches),
                    "matched": [
                        {"policy": name, "path": r.get("path",""), "capabilities": r.get("capabilities", [])}
                        for name, r in matches
                    ] if args.show_matches else None,
                }
            print(json.dumps(payload, indent=2))
        else:
            print(f"File: {target}")
            print("Stats:", res["stats"])
            if res["errors"]:
                print("\nSyntax errors:")
                for e in res["errors"]:
                    print("-", e)
            if res["overlaps"]:
                print("\nOverlaps:")
                for k, v in res["overlaps"].items():
                    print(f"- {k} -> {len(v)} rules")
                for s in suggest_optimizations(res["overlaps"]):
                    print("-", s)
            if res["risky"]:
                print("\nRisk findings:")
                for m in res["risky"]:
                    print("-", m)

            if args.check_path and args.capability:
                pols = [{"name": target.name, "rules": res["rules"]}]
                exit_code = run_permission_check(pols, args.check_path, args.capability, args.show_matches)

    elif target.is_dir():
        policies, totals, per_file = load_policies_from_folder(target, args.exts, args.severity)

        if args.json:
            payload = {
                "folder": str(target),
                "totals": totals,
                "files": [
                    {
                        "file": r.get("file"),
                        "stats": r.get("stats"),
                        "errors": r.get("errors"),
                        "overlaps": {k: len(v) for k, v in (r.get("overlaps") or {}).items()},
                        "risky": r.get("risky"),
                    }
                    for r in per_file
                ],
            }
            if args.check_path and args.capability:
                matches, all_caps = check_policies(policies, args.check_path, args.capability)
                payload["permission_check"] = {
                    "path": args.check_path,
                    "capability": args.capability,
                    "granted": args.capability in all_caps and "deny" not in all_caps,
                    "denied": "deny" in all_caps,
                    "matched_count": len(matches),
                    "matched": [
                        {"policy": name, "path": r.get("path",""), "capabilities": r.get("capabilities", [])}
                        for name, r in matches
                    ] if args.show_matches else None,
                }
            print(json.dumps(payload, indent=2))
        else:
            print(f"Folder: {target}")
            print("Totals:", totals)

            for r in per_file:
                if r["errors"] or r["overlaps"] or r["risky"]:
                    print(f"\n{r['file']}:")
                    if r["errors"]:
                        print("  Syntax errors:")
                        for e in r["errors"]:
                            print("   -", e)
                    if r["overlaps"]:
                        print("  Overlaps:")
                        for k, v in r["overlaps"].items():
                            print(f"   - {k} -> {len(v)} rules")
                        for s in suggest_optimizations(r["overlaps"]):
                            print("   -", s)
                    if r["risky"]:
                        print("  Risk findings:")
                        for m in r["risky"]:
                            print("   -", m)

            if args.check_path and args.capability:
                exit_code = run_permission_check(policies, args.check_path, args.capability, args.show_matches)
    else:
        print("Path is neither a file nor a folder", file=sys.stderr)
        return 1

    return exit_code

if __name__ == "__main__":
    sys.exit(main())
