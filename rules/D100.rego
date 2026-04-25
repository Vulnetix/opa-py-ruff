# SPDX-License-Identifier: Apache-2.0
# Ruff rule D100 (pydocstyle): undocumented public module
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d100

import rego.v1

metadata := {
	"id": "RUFF-D100",
	"name": "undocumented public module",
	"description": "Missing docstring in public module",
	"help_uri": "https://docs.astral.sh/ruff/rules/undocumented-public-module/",
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
	"ruff_code": "D100",
	"ruff_linter": "pydocstyle",
	"ruff_name": "undocumented-public-module",
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
