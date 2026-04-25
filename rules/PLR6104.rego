# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR6104 (Pylint): non augmented assignment
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr6104

import rego.v1

metadata := {
	"id": "RUFF-PLR6104",
	"name": "non augmented assignment",
	"description": "Use `<value>` to perform an augmented assignment directly",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-augmented-assignment/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR6104",
	"ruff_linter": "Pylint",
	"ruff_name": "non-augmented-assignment",
	"ruff_since": "v0.3.7",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
