# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0133 (Pylint): useless exception statement
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0133

import rego.v1

metadata := {
	"id": "RUFF-PLW0133",
	"name": "useless exception statement",
	"description": "Missing `raise` statement on exception",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-exception-statement/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0133",
	"ruff_linter": "Pylint",
	"ruff_name": "useless-exception-statement",
	"ruff_since": "0.5.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
