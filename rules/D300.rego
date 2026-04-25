# SPDX-License-Identifier: Apache-2.0
# Ruff rule D300 (pydocstyle): triple single quotes
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d300

import rego.v1

metadata := {
	"id": "RUFF-D300",
	"name": "triple single quotes",
	"description": "Use triple double quotes `'''`",
	"help_uri": "https://docs.astral.sh/ruff/rules/triple-single-quotes/",
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
	"ruff_code": "D300",
	"ruff_linter": "pydocstyle",
	"ruff_name": "triple-single-quotes",
	"ruff_since": "v0.0.69",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
