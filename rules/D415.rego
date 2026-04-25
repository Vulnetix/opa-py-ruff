# SPDX-License-Identifier: Apache-2.0
# Ruff rule D415 (pydocstyle): missing terminal punctuation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d415

import rego.v1

metadata := {
	"id": "RUFF-D415",
	"name": "missing terminal punctuation",
	"description": "First line should end with a period, question mark, or exclamation point",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-terminal-punctuation/",
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
	"ruff_code": "D415",
	"ruff_linter": "pydocstyle",
	"ruff_name": "missing-terminal-punctuation",
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
