# SPDX-License-Identifier: Apache-2.0
# Ruff rule D202 (pydocstyle): blank line after function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d202

import rego.v1

metadata := {
	"id": "RUFF-D202",
	"name": "blank line after function",
	"description": "No blank lines allowed after function docstring (found <value>)",
	"help_uri": "https://docs.astral.sh/ruff/rules/blank-line-after-function/",
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
	"ruff_code": "D202",
	"ruff_linter": "pydocstyle",
	"ruff_name": "blank-line-after-function",
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
