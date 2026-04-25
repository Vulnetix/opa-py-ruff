# SPDX-License-Identifier: Apache-2.0
# Ruff rule D200 (pydocstyle): unnecessary multiline docstring
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d200

import rego.v1

metadata := {
	"id": "RUFF-D200",
	"name": "unnecessary multiline docstring",
	"description": "One-line docstring should fit on one line",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-multiline-docstring/",
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
	"ruff_code": "D200",
	"ruff_linter": "pydocstyle",
	"ruff_name": "unnecessary-multiline-docstring",
	"ruff_since": "v0.0.68",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
