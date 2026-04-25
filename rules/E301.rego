# SPDX-License-Identifier: Apache-2.0
# Ruff rule E301 (pycodestyle): blank line between methods
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e301

import rego.v1

metadata := {
	"id": "RUFF-E301",
	"name": "blank line between methods",
	"description": "Expected <value> blank line, found 0",
	"help_uri": "https://docs.astral.sh/ruff/rules/blank-line-between-methods/",
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
	"ruff_code": "E301",
	"ruff_linter": "pycodestyle",
	"ruff_name": "blank-line-between-methods",
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
