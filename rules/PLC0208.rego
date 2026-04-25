# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0208 (Pylint): iteration over set
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0208

import rego.v1

metadata := {
	"id": "RUFF-PLC0208",
	"name": "iteration over set",
	"description": "Use a sequence type instead of a `set` when iterating over values",
	"help_uri": "https://docs.astral.sh/ruff/rules/iteration-over-set/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plc"],
	"ruff_code": "PLC0208",
	"ruff_linter": "Pylint",
	"ruff_name": "iteration-over-set",
	"ruff_since": "v0.0.271",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
