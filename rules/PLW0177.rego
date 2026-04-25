# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0177 (Pylint): nan comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0177

import rego.v1

metadata := {
	"id": "RUFF-PLW0177",
	"name": "nan comparison",
	"description": "Comparing against a NaN value; use `math.isnan` instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/nan-comparison/",
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
	"ruff_code": "PLW0177",
	"ruff_linter": "Pylint",
	"ruff_name": "nan-comparison",
	"ruff_since": "0.12.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
