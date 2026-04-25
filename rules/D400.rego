# SPDX-License-Identifier: Apache-2.0
# Ruff rule D400 (pydocstyle): missing trailing period
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d400

import rego.v1

metadata := {
	"id": "RUFF-D400",
	"name": "missing trailing period",
	"description": "First line should end with a period",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-trailing-period/",
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
	"ruff_code": "D400",
	"ruff_linter": "pydocstyle",
	"ruff_name": "missing-trailing-period",
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
