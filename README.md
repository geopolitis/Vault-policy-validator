# Vault Policy Validator

Validate, lint, and analyze **Vault HCL policies**. Ships with a **CLI** and a **UI**.
Parses best-effort (never blocks), reports all findings, and evaluates permissions with Vault-style precedence.

## Features

* **HCL parsing & syntax checks**

  * Balanced braces/brackets/quotes
  * `capabilities = [...]` must be **quoted** and **valid**
  * Unknown keys flagged as `[low]`
  * Commented-out rules detected as `[low]`

* **Decision engine**

  * Exact literal > `+` (one segment) > `*` (suffix)
  * Trailing `*` inside segment (e.g. `foo*`) = segment prefix
  * Most-specific cohort wins; `deny` on the best cohort overrides
  * `ALLOW | DENY | NOT_MATCHED`

* **Linting**

  * Overlaps: identical literal paths in multiple rules (suggest merge)
  * Wildcard + high-risk capabilities (default: `delete, sudo, update, patch, revoke`)
  * Commented-out “rules”

* **Consistent Stats (CLI & UI)**

  * Files searched, policies parsed, syntax errors, overlaps, high/low/risky counts

* **Output**

  * Human-readable
  * JSON schema for automation
  * Severity filtering: `all | high | risky | low`

---

## Project Layout

```
policy_validator/
  __init__.py          # dataclasses: Rule, Finding, Stats (no imports here)
  parser.py            # HCL parsing + syntax validation
  matcher.py           # path matching and specificity
  priority.py          # precedence & decision (“decide”, “cohort_and_caps”)
  lints.py             # structured linters + stats aggregator
  cli.py               # argparse CLI
  ui.py                # Streamlit UI
tests/
  test_policy_validator.py
pyproject.toml
.coveragerc
pytest.ini
README.md
```

---

## Install

Requires **Python 3.11+**.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

If you’re only running the CLI:

```bash
python -m pip install -e ".[cli]"
```

(Or just keep the editable install; dependencies are light.)

---

## Run the UI

```bash
streamlit run policy_validator/ui.py
```

* **Sidebar**: choose *Single file* or *Scan folder*, set **Severity** filter, upload/scan from the sidebar, live **Statistics**.
* **Main**: set **Request Path** and **Capability**, paste/edit policy text, view **Syntax**, **Findings**, and **Decision**.
* “Matched rules (highest specificity)” shows the winning cohort and effective capabilities.

> Tip: If you ever see “attempted relative import” from Streamlit, you’re probably running from a non-package context. This repo includes an **import shim** in `ui.py` that handles both `streamlit run policy_validator/ui.py` and module mode.

---

## Run the CLI

### Basic

```bash
python -m policy_validator.cli --file policy.hcl --path secret/data/foo --cap read
```

### Folder scan

```bash
python -m policy_validator.cli --scan-folder ./policies --exts ".hcl,.policy,.txt" \
  --path prod/secret/data/foo/bar --cap update
```

### Severity filter

```bash
python -m policy_validator.cli --file policy.hcl --severity risky
```

### JSON output

```bash
python -m policy_validator.cli --file policy.hcl --json > report.json
```

#### Sample human output

```
Statistics
- files: 1
- policies: 6
- syntax: 0
- overlaps: 2
- high: 1
- low: 2
- risky: 0

Syntax messages:
- [low] Commented-out rules detected (lines starting with #). Consider removing them.

Findings (severity=all):
- [low] OVERLAP: secret/data/foo appears in 2 rules. Suggestion: merge rules for path secret/data/foo.
- [high] WILDCARD_DELETE: Wildcard path 'secret/*' grants high-risk capabilities ['delete'].

Decision: ALLOW

Matched rules (highest specificity):
- policy.hcl:42  path "secret/data/foo" -> ['read', 'update']
Effective caps on best path: ['read', 'update']
```

#### JSON shape (simplified)

```json
{
  "severity": "all",
  "stats": { "files": 1, "policies": 6, "syntax": 0, "overlaps": 2, "high": 1, "low": 2, "risky": 0 },
  "syntax": ["..."],
  "findings": [
    {"severity":"low","code":"OVERLAP","message":"...","path":"secret/data/foo","source":null,"lineno":null}
  ],
  "findings_visible": [ /* filtered by --severity */ ],
  "decision": {
    "path": "secret/data/foo",
    "capability": "read",
    "result": "ALLOW",
    "cohort": [
      {"path":"secret/data/foo","capabilities":["read","update"],"source":"policy.hcl","lineno":42}
    ],
    "caps": ["read","update"]
  }
}
```

**Exit codes**: `0` success; `2` if **syntax errors** (non-low) are present.

---

## Policy Semantics

### Supported Capabilities (strict)

```
create, read, update, patch, delete, list, sudo, deny, subscribe, revoke
```

Unknown capabilities → **syntax/validation error**.

### Wildcards

* `+` matches **exactly one** segment: `kv/+/data` matches `kv/app/data`, not `kv/app/x/data`.
* Final segment `*` matches **any suffix**: `secret/foo/*` matches `secret/foo` and deeper.
* Trailing star inside a segment: `secret/foo*` matches `secret/foobar`.

### Precedence (specificity)

Higher is better:

1. number of **non-wildcard** segments
2. **total** segments
3. **fewer** wildcards (`+`, `*`, `foo*`)

On the **best cohort**:

* If **any** rule has `deny` → **DENY**
* Else union capabilities → **ALLOW** if requested capability present
* Otherwise **NOT\_MATCHED**

---

## Linting Rules

* **OVERLAP (low)**: same literal path appears in multiple rules. Suggests merging.
* \**WILDCARD\_* (high)\*\*: wildcard path combined with **high-risk** capability (`delete, sudo, update, patch, revoke`).
* **COMMENTED\_RULE (low)**: lines starting with `#` that look like path/capabilities.

---

## Development

### Tests & Coverage

```bash
pytest -v
# or with coverage
pytest --cov=policy_validator --cov-report=term-missing
```

Coverage thresholds are configured in `pyproject.toml` / `.coveragerc`.
CLI/UI are omitted from coverage by default (adjust `.coveragerc` if you want them included).

### Static typing

```bash
mypy policy_validator
```

> If mypy flags local variables needing annotations, follow the pattern:
> `var: list[str] = []`

---

## API Overview (for library use)

```python
from policy_validator.parser import parse_vault_policy, hcl_syntax_check, CAPABILITIES, VALID_CAPS
from policy_validator.priority import decide, cohort_and_caps
from policy_validator.lints import lint_overlaps, lint_risky, lint_commented_rules, aggregate_stats

text = 'path "secret/*" { capabilities = ["read"] }'
errors = hcl_syntax_check(text)               # list[str]
rules  = parse_vault_policy(text, source="inline")

cohort, caps = cohort_and_caps(rules, "secret/foo")
decision     = decide(rules, "secret/foo", "read")  # "ALLOW" | "DENY" | "NOT_MATCHED"

findings = []
findings += lint_overlaps(rules)
findings += lint_risky(rules)
findings += lint_commented_rules({"inline": text})

stats = aggregate_stats(findings, files=1, policies=len(rules), syntax_errors=len([e for e in errors if not e.lower().startswith("[low]")]))
```

---

## Troubleshooting

* **“attempted relative import with no known parent package”**
  Use `streamlit run policy_validator/ui.py` or `python -m policy_validator.cli`. Import shims in UI/CLI handle both modes.

* **UI shows syntax warnings and stops**
  This app is **non-blocking**: parsing, linting, and decisions always run. If you see stalls, ensure you’re on the current `ui.py`.

* **Coverage under threshold**
  By default we omit UI/CLI in `.coveragerc`. Include them or add tests if you prefer counting them.

