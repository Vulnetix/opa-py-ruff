# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0206 (Pylint): dict index missing items
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0206

import rego.v1

metadata := {
	"id": "RUFF-PLC0206",
	"name": "dict index missing items",
	"description": "Extracting value from dictionary without calling `.items()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/dict-index-missing-items/",
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
	"ruff_code": "PLC0206",
	"ruff_linter": "Pylint",
	"ruff_name": "dict-index-missing-items",
	"ruff_since": "0.8.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
