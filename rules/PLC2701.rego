# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC2701 (Pylint): import private name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc2701

import rego.v1

metadata := {
	"id": "RUFF-PLC2701",
	"name": "import private name",
	"description": "Private name import `<value>` from external module `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/import-private-name/",
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
	"ruff_code": "PLC2701",
	"ruff_linter": "Pylint",
	"ruff_name": "import-private-name",
	"ruff_since": "v0.1.14",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
