# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP030 (pyupgrade): format literals
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up030

import rego.v1

metadata := {
	"id": "RUFF-UP030",
	"name": "format literals",
	"description": "Use implicit references for positional format fields",
	"help_uri": "https://docs.astral.sh/ruff/rules/format-literals/",
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
	"ruff_code": "UP030",
	"ruff_linter": "pyupgrade",
	"ruff_name": "format-literals",
	"ruff_since": "v0.0.218",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
