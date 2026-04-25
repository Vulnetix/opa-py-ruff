# SPDX-License-Identifier: Apache-2.0
# Ruff rule E302 (pycodestyle): blank lines top level
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e302

import rego.v1

metadata := {
	"id": "RUFF-E302",
	"name": "blank lines top level",
	"description": "Expected <value> blank lines, found <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/blank-lines-top-level/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E302",
	"ruff_linter": "pycodestyle",
	"ruff_name": "blank-lines-top-level",
	"ruff_since": "v0.2.2",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
