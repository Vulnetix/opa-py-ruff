# SPDX-License-Identifier: Apache-2.0
# Ruff rule D105 (pydocstyle): undocumented magic method
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d105

import rego.v1

metadata := {
	"id": "RUFF-D105",
	"name": "undocumented magic method",
	"description": "Missing docstring in magic method",
	"help_uri": "https://docs.astral.sh/ruff/rules/undocumented-magic-method/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pydocstyle", "d"],
	"ruff_code": "D105",
	"ruff_linter": "pydocstyle",
	"ruff_name": "undocumented-magic-method",
	"ruff_since": "v0.0.70",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
