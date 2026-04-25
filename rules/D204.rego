# SPDX-License-Identifier: Apache-2.0
# Ruff rule D204 (pydocstyle): incorrect blank line after class
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d204

import rego.v1

metadata := {
	"id": "RUFF-D204",
	"name": "incorrect blank line after class",
	"description": "1 blank line required after class docstring",
	"help_uri": "https://docs.astral.sh/ruff/rules/incorrect-blank-line-after-class/",
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
	"ruff_code": "D204",
	"ruff_linter": "pydocstyle",
	"ruff_name": "incorrect-blank-line-after-class",
	"ruff_since": "v0.0.70",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
