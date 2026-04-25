# SPDX-License-Identifier: Apache-2.0
# Ruff rule D201 (pydocstyle): blank line before function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d201

import rego.v1

metadata := {
	"id": "RUFF-D201",
	"name": "blank line before function",
	"description": "No blank lines allowed before function docstring (found <value>)",
	"help_uri": "https://docs.astral.sh/ruff/rules/blank-line-before-function/",
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
	"ruff_code": "D201",
	"ruff_linter": "pydocstyle",
	"ruff_name": "blank-line-before-function",
	"ruff_since": "v0.0.70",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
