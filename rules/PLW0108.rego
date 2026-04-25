# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0108 (Pylint): unnecessary lambda
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0108

import rego.v1

metadata := {
	"id": "RUFF-PLW0108",
	"name": "unnecessary lambda",
	"description": "Lambda may be unnecessary; consider inlining inner function",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-lambda/",
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
	"ruff_code": "PLW0108",
	"ruff_linter": "Pylint",
	"ruff_name": "unnecessary-lambda",
	"ruff_since": "0.15.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
