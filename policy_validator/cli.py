from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple
try:
    from . import Rule, Finding, Stats
    from .parser import hcl_syntax_check, parse_vault_policy
    from .priority import decide, cohort_and_caps
    from .lints import lint_overlaps, lint_risky, lint_commented_rules, aggregate_stats
except Exception:
    import sys as _sys, pathlib as _pathlib
    _ROOT = _pathlib.Path(__file__).resolve().parents[1]
    _sys.path.insert(0, str(_ROOT))
    from policy_validator import Rule, Finding, Stats
    from policy_validator.parser import hcl_syntax_check, parse_vault_policy
    from policy_validator.priority import decide, cohort_and_caps
    from policy_validator.lints import lint_overlaps, lint_risky, lint_commented_rules, aggregate_stats

class _Palette:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BRIGHT_CYAN = "\033[96m"
    GREY = "\033[90m"

def _should_color(mode: str) -> bool:
    """Decide if we should emit ANSI colors."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    # auto
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def _try_enable_windows_color() -> None:
    # Optional support if colorama is present; safe no-op otherwise.
    try:
        import colorama  # type: ignore
        colorama.just_fix_windows_console()
    except Exception:
        pass

def _clr(enabled: bool, text: str, *styles: str) -> str:
    if not enabled or not styles:
        return text
    return "".join(styles) + text + _Palette.RESET

def _analyze_text(text: str, source: str) -> Tuple[List[str], List[Rule]]:
    errs = hcl_syntax_check(text)
    rules = parse_vault_policy(text, source=source)
    return errs, rules

def _collect_from_folder(folder: Path, exts: List[str]) -> Tuple[List[str], List[Rule], Dict[str, str]]:
    errs: List[str] = []
    rules: List[Rule] = []
    texts: Dict[str, str] = {}
    for p in folder.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            txt = p.read_text(encoding="utf-8", errors="replace")
            e, r = _analyze_text(txt, source=str(p))
            texts[str(p)] = txt
            errs.extend(e)
            rules.extend(r)
    return errs, rules, texts

def _filter_findings(findings: List[Finding], severity: str) -> List[Finding]:
    if severity == "all":
        return findings
    return [f for f in findings if f.severity == severity]

def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HashiCorp Vault policy validator")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="Single policy file (.hcl)")
    src.add_argument("--scan-folder", type=Path, help="Scan folder for .hcl files")

    ap.add_argument("--path", dest="req_path", default="", help="Request path to check (e.g., secret/data/foo/bar)")
    ap.add_argument("--cap", dest="capability", default="", help="Capability to check (e.g., read)")
    ap.add_argument("--severity", choices=["all", "high", "risky", "low"], default="all",
                    help="Filter which findings are shown (stats are unaffected).")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable")
    ap.add_argument("--exts", default=".hcl,.policy,.txt", help="Extensions for --scan-folder")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="Colorize output (default: auto)")
    args = ap.parse_args(argv)

    color_enabled = _should_color(args.color) and not args.json
    if color_enabled:
        _try_enable_windows_color()

    all_errs: List[str] = []
    all_rules: List[Rule] = []
    texts_by_source: Dict[str, str] = {}
    files_count = 0

    if args.file:
        files_count = 1
        text = args.file.read_text(encoding="utf-8", errors="replace")
        all_errs, all_rules = _analyze_text(text, source=str(args.file))
        texts_by_source[str(args.file)] = text
    else:
        folder = args.scan_folder
        exts = {e.strip().lower() for e in args.exts.split(",") if e.strip()}
        err, rules, texts = _collect_from_folder(folder, list(exts))
        files_count = len(texts)
        all_errs, all_rules = err, rules
        texts_by_source = texts

    # Lints
    findings: List[Finding] = []
    findings.extend(lint_overlaps(all_rules))
    findings.extend(lint_risky(all_rules))
    findings.extend(lint_commented_rules(texts_by_source))

    # Stats (syntax errors are counted as non-[low])
    fatal_syntax = [e for e in all_errs if not e.lower().startswith("[low]")]
    stats = aggregate_stats(findings, files=files_count, policies=len(all_rules), syntax_errors=len(fatal_syntax))

    # Apply severity filter for display/JSON (stats remain totals)
    visible_findings = _filter_findings(findings, args.severity)

    if args.json:
        cohort, caps = cohort_and_caps(all_rules, args.req_path) if args.req_path else ([], set())
        decision = decide(all_rules, args.req_path, args.capability) if args.req_path and args.capability else None
        payload = {
            "severity": args.severity,
            "stats": stats.__dict__,
            "syntax": all_errs,
            "findings": [f.__dict__ for f in findings],                   # all
            "findings_visible": [f.__dict__ for f in visible_findings],   # filtered
            "decision": {
                "path": args.req_path,
                "capability": args.capability,
                "result": decision,
                "cohort": [r.__dict__ for r in cohort],
                "caps": sorted(list(caps)),
            } if args.req_path and args.capability else None,
        }
        print(json.dumps(payload, indent=2))
        return 2 if len(fatal_syntax) > 0 else 0

    # ----------- Human-readable (colored) -----------
    H = _Palette  # alias

    # Statistics
    print(_clr(color_enabled, "Statistics", H.BRIGHT_CYAN, H.BOLD))
    for k, v in stats.__dict__.items():
        key = _clr(color_enabled, f"- {k}:", H.GREY)
        val = _clr(color_enabled, str(v), H.BOLD)
        print(f"{key} {val}")

    # Syntax
    print()
    print(_clr(color_enabled, "Syntax messages:", H.BRIGHT_CYAN))
    if all_errs:
        for e in all_errs:
            is_low = e.lower().startswith("[low]")
            style = (H.YELLOW,) if is_low else (H.RED, H.BOLD)
            print(_clr(color_enabled, f"- {e}", *style))
    else:
        print(_clr(color_enabled, "- none", H.GREY))

    # Findings
    print()
    print(_clr(color_enabled, f"Findings (severity={args.severity}):", H.BRIGHT_CYAN))
    if visible_findings:
        for f in visible_findings:
            if f.severity == "high":
                tag = _clr(color_enabled, "[high]", H.RED, H.BOLD)
            elif f.severity == "risky":
                tag = _clr(color_enabled, "[risky]", H.YELLOW, H.BOLD)
            else:
                tag = _clr(color_enabled, "[low]", H.BLUE)
            loc = f" ({f.source}:{f.lineno})" if f.source and f.lineno else ""
            msg = f"{tag} {f.code}: {f.message}{loc}"
            print(f"- {msg}")
    else:
        print(_clr(color_enabled, "- none", H.GREY))

    # Decision & Matched cohort
    if args.req_path and args.capability:
        print()
        result = decide(all_rules, args.req_path, args.capability)
        if result == "ALLOW":
            res_col = (H.GREEN, H.BOLD)
        elif result == "DENY":
            res_col = (H.RED, H.BOLD)
        else:
            res_col = (H.YELLOW, H.BOLD)
        print(_clr(color_enabled, f"Decision: {result}", *res_col))

        # Show matched cohort like UI
        cohort, caps = cohort_and_caps(all_rules, args.req_path)
        print()
        print(_clr(color_enabled, "Matched rules (highest specificity):", H.BRIGHT_CYAN))
        if cohort:
            for r in cohort:
                caps_list = sorted(r.capabilities)
                loc = f"{r.source}:{r.lineno}" if r.source else "(inline)"
                path_str = _clr(color_enabled, f"\"{r.path}\"", H.CYAN)
                caps_str = _clr(color_enabled, str(caps_list), H.BOLD)
                print(f"- {loc}  path {path_str} -> {caps_str}")
            eff = _clr(color_enabled, "Effective caps on best path:", H.GREY)
            caps_eff = _clr(color_enabled, str(sorted(list(caps))), H.BOLD)
            print(f"{eff} {caps_eff}")
        else:
            print(_clr(color_enabled, "- none (no rules match this path)", H.GREY))

    return 2 if len(fatal_syntax) > 0 else 0
if __name__ == "__main__":
    raise SystemExit(main())
