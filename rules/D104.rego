# SPDX-License-Identifier: Apache-2.0
# Ruff rule D104 (pydocstyle): undocumented public package
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d104

import rego.v1

metadata := {
	"id": "RUFF-D104",
	"name": "undocumented public package",
	"description": "Missing docstring in public package",
	"help_uri": "https://docs.astral.sh/ruff/rules/undocumented-public-package/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pydocstyle", "d"],
	"ruff_code": "D104",
	"ruff_linter": "pydocstyle",
	"ruff_name": "undocumented-public-package",
	"ruff_since": "v0.0.70",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
