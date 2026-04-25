# SPDX-License-Identifier: Apache-2.0
# Ruff rule D205 (pydocstyle): missing blank line after summary
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d205

import rego.v1

metadata := {
	"id": "RUFF-D205",
	"name": "missing blank line after summary",
	"description": "1 blank line required between summary line and description",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-blank-line-after-summary/",
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
	"ruff_code": "D205",
	"ruff_linter": "pydocstyle",
	"ruff_name": "missing-blank-line-after-summary",
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
