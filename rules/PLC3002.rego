# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC3002 (Pylint): unnecessary direct lambda call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc3002

import rego.v1

metadata := {
	"id": "RUFF-PLC3002",
	"name": "unnecessary direct lambda call",
	"description": "Lambda expression called directly. Execute the expression inline instead.",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-direct-lambda-call/",
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
	"ruff_code": "PLC3002",
	"ruff_linter": "Pylint",
	"ruff_name": "unnecessary-direct-lambda-call",
	"ruff_since": "v0.0.153",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
