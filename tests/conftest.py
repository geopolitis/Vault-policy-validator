# tests/conftest.py
import sys, types, importlib.util, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # usually enough

try:
    import policy_validator  # already importable? great—do nothing else.
except Exception:
    # Fallback: dynamically load from either ROOT or ROOT/policy_validator
    SRC = None
    for cand in (ROOT / "policy_validator", ROOT):
        if (cand / "matcher.py").exists() and (cand / "parser.py").exists():
            SRC = cand
            break
    if SRC is None:
        raise FileNotFoundError(f"Could not locate matcher.py/parser.py under {ROOT} or {ROOT/'policy_validator'}")

    def _load(name: str, file: str):
        spec = importlib.util.spec_from_file_location(name, str(SRC / file))
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod

    # Build a minimal package so 'from policy_validator import matcher' works
    pkg = types.ModuleType("policy_validator")
    pkg.__path__ = [str(SRC)]
    matcher = _load("policy_validator.matcher", "matcher.py")
    pkg.matcher = matcher
    sys.modules["policy_validator"] = pkg
    sys.modules["policy_validator.matcher"] = matcher

    # Load the rest
    parser = _load("policy_validator.parser", "parser.py")
    lints = _load("policy_validator.lints", "lints.py")
    priority = _load("policy_validator.priority", "priority.py")
    pkg.parser = parser
    pkg.lints = lints
    pkg.priority = priority
    sys.modules["policy_validator.parser"] = parser
    sys.modules["policy_validator.lints"] = lints
    sys.modules["policy_validator.priority"] = priority
