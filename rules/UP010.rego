# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP010 (pyupgrade): unnecessary future import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up010

import rego.v1

metadata := {
	"id": "RUFF-UP010",
	"name": "unnecessary future import",
	"description": "Unnecessary `__future__` import `<value>` for target Python version",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-future-import/",
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
	"ruff_code": "UP010",
	"ruff_linter": "pyupgrade",
	"ruff_name": "unnecessary-future-import",
	"ruff_since": "v0.0.155",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
