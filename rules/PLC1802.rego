# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC1802 (Pylint): len test
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc1802

import rego.v1

metadata := {
	"id": "RUFF-PLC1802",
	"name": "len test",
	"description": "`len(<value>)` used as condition without comparison",
	"help_uri": "https://docs.astral.sh/ruff/rules/len-test/",
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
	"ruff_code": "PLC1802",
	"ruff_linter": "Pylint",
	"ruff_name": "len-test",
	"ruff_since": "0.10.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
