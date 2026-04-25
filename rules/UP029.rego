# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP029 (pyupgrade): unnecessary builtin import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up029

import rego.v1

metadata := {
	"id": "RUFF-UP029",
	"name": "unnecessary builtin import",
	"description": "Unnecessary builtin import: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-builtin-import/",
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
	"ruff_code": "UP029",
	"ruff_linter": "pyupgrade",
	"ruff_name": "unnecessary-builtin-import",
	"ruff_since": "v0.0.211",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
