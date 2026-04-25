# SPDX-License-Identifier: Apache-2.0
# Ruff rule D416 (pydocstyle): missing section name colon
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d416

import rego.v1

metadata := {
	"id": "RUFF-D416",
	"name": "missing section name colon",
	"description": "Section name should end with a colon ('<value>')",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-section-name-colon/",
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
	"ruff_code": "D416",
	"ruff_linter": "pydocstyle",
	"ruff_name": "missing-section-name-colon",
	"ruff_since": "v0.0.74",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
