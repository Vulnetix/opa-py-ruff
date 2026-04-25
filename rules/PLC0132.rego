# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0132 (Pylint): type param name mismatch
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0132

import rego.v1

metadata := {
	"id": "RUFF-PLC0132",
	"name": "type param name mismatch",
	"description": "`<value>` name `<value>` does not match assigned variable name `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-param-name-mismatch/",
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
	"ruff_code": "PLC0132",
	"ruff_linter": "Pylint",
	"ruff_name": "type-param-name-mismatch",
	"ruff_since": "v0.0.277",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
