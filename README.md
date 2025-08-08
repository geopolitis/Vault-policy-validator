# Vault Policy Permission Checker (HCL Format)

This is a tool that validates and analyzes HashiCorp Vault policies written in HCL format.  
It helps you verify whether a given path and capability are permitted by your policies, and also detects overlapping ACL rules for optimization.

---

## Features

- **Syntax Validation**  
  Checks for:
  - Unmatched quotes and braces
  - Missing or malformed `capabilities` blocks
  - Missing `path` blocks

- **Permission Checking**  
  Given a request path and capability (e.g., `read`), determines if **any** matching policy grants that capability using Vault’s path matching rules.

- **Effective Capability Calculation**  
  Displays all capabilities granted for the highest-priority matching rule(s).

- **Overlap Detection**  
  Finds and reports paths with multiple ACL definitions, suggesting optimizations.

---

## Example Usage

1. Paste your Vault HCL policy blocks into the text area.
2. Enter the **request path** you want to check (e.g., `/secret/data/myapp`).
3. Select the **operation** (capability) from the dropdown.
4. Click **"Check Permission"** to see if it’s granted.

Example Policy Block:

```hcl
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "secret/data/myapp/config" {
  capabilities = ["read", "update"]
}
```

---

## Generated Example Policies

Below is an example set of randomly generated policies for testing:

```hcl
path "segment10/segment8/segment4/segment3" {
  capabilities = ["update", "read", "sudo", "create"]
}

path "segment5/segment5/segment6/segment1" {
  capabilities = ["read", "list", "delete"]
}

path "segment8/segment9/segment7" {
  capabilities = ["read", "create"]
}

path "segment6/segment6/segment6" {
  capabilities = ["update"]
}

path "segment2/segment4/segment10/segment2" {
  capabilities = ["read", "sudo"]
}

path "segment5/segment8/segment6/segment4" {
  capabilities = ["update", "list", "read", "delete"]
}

path "segment4/segment8/segment8/*" {
  capabilities = ["read", "create", "update"]
}
```

---

## Installation

1. Clone this repository or copy the script to your local machine.
2. Install dependencies:

```bash
pip install streamlit
```

3. Run the app:

```bash
streamlit run app.py
```

---

## Notes

- Currently, only the `capabilities` attribute is checked; other Vault ACL attributes like `control_group` are ignored.
- Wildcard (`*`) matching is supported using Python’s `fnmatch`.
- Overlap detection is based on normalized paths (wildcards removed).

---

## License

MIT License
