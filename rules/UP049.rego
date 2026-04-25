# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP049 (pyupgrade): private type parameter
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up049

import rego.v1

metadata := {
	"id": "RUFF-UP049",
	"name": "private type parameter",
	"description": "Generic {} uses private type parameters",
	"help_uri": "https://docs.astral.sh/ruff/rules/private-type-parameter/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP049",
	"ruff_linter": "pyupgrade",
	"ruff_name": "private-type-parameter",
	"ruff_since": "0.12.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
