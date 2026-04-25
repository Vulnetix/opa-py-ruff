# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF021 (Ruff-specific rules): parenthesize chained operators
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf021

import rego.v1

metadata := {
	"id": "RUFF-RUF021",
	"name": "parenthesize chained operators",
	"description": "Parenthesize `a and b` expressions when chaining `and` and `or` together, to make the precedence clear",
	"help_uri": "https://docs.astral.sh/ruff/rules/parenthesize-chained-operators/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF021",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "parenthesize-chained-operators",
	"ruff_since": "0.8.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
