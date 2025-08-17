# Vault Policy Validator (Streamlit + CLI)

A fast, lightweight validator for **HashiCorp Vault** policies. It parses HCL-like policy blocks, checks for common mistakes, flags risky grants, and evaluates whether a given **request path + capability** would be allowed by the **highest-priority** matching rule. Comes with both a Streamlit UI and a CLI to use with CI/CD pipelines, plus pytest tests.

---

## ✨ Features

- **Two UIs**  
  - **Streamlit app**: paste/upload a policy or scan a folder; interactive results.  
  - **CLI**: validate files/folders; run permission checks; JSON output.

- **Policy parsing (HCL-like)**  
  - Supports both `path("pattern") { ... }` and `path "pattern" { ... }`.  
  - Detects **unquoted** capabilities in lists (e.g. `[read, list]`).  
  - Flags unmatched braces and quotes; strips `#`-prefixed full-line comments.

- **Risk & quality checks**
  - Overlapping ACL paths.  
  - Risky wildcard usage (e.g., wildcard + `update`/`delete`/`sudo`).  
  - Suggestions to merge identical rules.

- **Priority evaluation**
  - Finds **all** matching rules and sorts by priority.  
  - **Exact** paths outrank wildcards.  
  - Longer literal prefix outranks shorter (`*`/`+` appear later).  
  - Fewer `+` segments outrank more `+`.  
  - Same-best-path rules from multiple policies are **unioned**.

- **Test suite** (pytest) and optional **coverage** (pytest-cov).

---

## 📦 Requirements

- Python **3.11+**  
- Pip + virtualenv recommended

---

## 🚀 Installation

From the repository root (the folder that contains `pyproject.toml`):

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip

# Editable install (recommended for development)
python -m pip install -e .
```

If you don’t want to install, you can still run the UI via Streamlit and the tests via a tiny `tests/conftest.py` shim (see below), but editable install is the simplest.

---

## 🖥️ Streamlit App

Run the app from the repo root:

```bash
streamlit run main.py
# (you can also run `ui.py`, but `main.py` is the consolidated app)
```

### Sidebar (order & actions)
1. **Mode**: `Single file` or `Scan folder`  
2. **Load policy**: `Upload file` (+ **Load File** button) or `Paste text` (use the big editor + **Check Policy**)  
3. **Request**: Request **Path** and desired **Capability**  
4. **Filter**: Filter results by severity (`all`, `high`, `low`, `syntax`, `risky`)  
5. **Statistics**: Files searched, policies parsed, syntax errors, overlaps, high/low/risky counts

### Main pane
- **Paste / Upload**: shows parsed rules, syntax errors, overlaps, and risk findings.  
- **Check Permission**: evaluates your selected request path + capability against the **highest-priority** matching path and explains the result (GRANTED / DENIED / not explicitly granted).  
- **Scan folder**: recursively walks the folder, filters by extensions (default: `.hcl,.txt,.policy`), aggregates stats, and shows per-file results.

---

## 🧰 CLI

Run the CLI without installing (local modules) or via the installed package.

**Local (repo root):**
```bash
python -m policy_validator.cli <path> [--severity all|high|low|syntax|risky] \
  [--exts .hcl,.txt,.policy] \
  [--check-path secret/data/foo --cap read] \
  [--show-matches] [--json]
```

**Examples**
```bash
# Validate one file
python -m policy_validator.cli ./examples/example.hcl --severity all

# Check a permission against that file
python -m policy_validator.cli ./examples/example.hcl \
  --check-path secret/data/myapp/config --cap read --show-matches

# Scan a folder and summarize
python -m policy_validator.cli ./policies --exts .hcl,.policy --json
```

**Exit codes**
- `0`: permission GRANTED  
- `2`: DENIED (explicit `deny` on the best path)  
- `3`: not explicitly granted  
- `1`: error (missing inputs / no policies)

---

## 🧩 Policy format & rules

- **Blocks**
  ```hcl
  path "kv/data/foo/*" { capabilities = ["read", "list"] }
  path("kv/data/bar")  { capabilities = "update" }
  ```
- **Capabilities** must be quoted in lists. The validator flags unquoted tokens:
  ```hcl
  capabilities = [read, list]   # ❌ will raise: Invalid or unquoted capabilities
  ```
- **Allowed capabilities** (extendable):  
  `create, read, update, patch, delete, list, sudo, deny, subscribe, recover`

- **Comments**: lines starting with `#` are ignored.

- **Wildcards**
  - `*` is a **suffix** wildcard and **only allowed at the end** of the path.  
    `path "secret/*/data"` → ❌ flagged as invalid.  
  - `+` matches a **single path segment** (e.g., `secret/+/data` matches `secret/app/data`).

- **Priority** (best match wins; caps are **unioned** across policies that match the **exact same best path**)
  1. Longer literal prefix (first wildcard appears **later**) is higher priority  
  2. Exact path (no `+` or `*`) outranks wildcard  
  3. Fewer `+` segments outrank more `+`  
  4. Longer path wins; then lexicographic tie-break

---

## 🧪 Tests

Install pytest (and optionally pytest-cov):

```bash
pip install -e .
pip install pytest pytest-cov
```

Run tests from the **repo root**:

```bash
pytest -q
```

### Coverage
```bash
pytest --cov=policy_validator --cov-report=term-missing --cov-branch
# or (if your modules live at root)
# pytest --cov=. --cov-report=term-missing --cov-branch
```

You can also configure defaults in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
addopts = "-q --cov=policy_validator --cov-report=term-missing --cov-branch"
testpaths = ["tests"]

[tool.coverage.run]
source = ["policy_validator"]
branch = true
omit = ["policy_validator/main.py", "policy_validator/ui.py"]  # optional

[tool.coverage.report]
show_missing = true
skip_covered = true
```

> If you want to run tests **without** installing the package, add this minimal `tests/conftest.py` so imports resolve:
> ```python
> import sys, pathlib
> sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
> ```

---

## 🗂️ Project layout (key files)

```
policy_validator/
├── __init__.py          # package facade/re-exports
├── matcher.py           # path matching (+ for one segment, * suffix)
├── priority.py          # comparator + check_policies()
├── parser.py            # HCL-like parsing & syntax checks
├── lints.py             # overlaps, risky grants, tiny helpers
├── main.py              # Streamlit app (consolidated)
├── ui.py                # Alternate Streamlit UI
├── cli.py               # CLI entry-point
└── tests/               # pytest tests (if present)
```

---

## ⚠️ Limitations

- The parser is **lightweight** and not a full HCL parser. It focuses on Vault policy patterns and common issues.
- Only `capabilities` are evaluated; advanced attributes (e.g., `control_group`) are currently ignored.
- `*` wildcard is validated as **suffix-only** by design (matches the app’s tests and lint rules).