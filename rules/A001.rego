# SPDX-License-Identifier: Apache-2.0
# Ruff rule A001 (flake8-builtins): builtin variable shadowing
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_a001

import rego.v1

metadata := {
	"id": "RUFF-A001",
	"name": "builtin variable shadowing",
	"description": "Variable `<value>` is shadowing a Python builtin",
	"help_uri": "https://docs.astral.sh/ruff/rules/builtin-variable-shadowing/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-builtins", "a"],
	"ruff_code": "A001",
	"ruff_linter": "flake8-builtins",
	"ruff_name": "builtin-variable-shadowing",
	"ruff_since": "v0.0.48",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
