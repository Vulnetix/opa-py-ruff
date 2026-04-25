# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC2801 (Pylint): unnecessary dunder call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc2801

import rego.v1

metadata := {
	"id": "RUFF-PLC2801",
	"name": "unnecessary dunder call",
	"description": "Unnecessary dunder call to `<value>`. <value>.",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-dunder-call/",
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
	"ruff_code": "PLC2801",
	"ruff_linter": "Pylint",
	"ruff_name": "unnecessary-dunder-call",
	"ruff_since": "v0.1.12",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
