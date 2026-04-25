# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW3201 (Pylint): bad dunder method name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw3201

import rego.v1

metadata := {
	"id": "RUFF-PLW3201",
	"name": "bad dunder method name",
	"description": "Dunder method `<value>` has no special meaning in Python 3",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-dunder-method-name/",
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
	"ruff_code": "PLW3201",
	"ruff_linter": "Pylint",
	"ruff_name": "bad-dunder-method-name",
	"ruff_since": "v0.0.285",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
