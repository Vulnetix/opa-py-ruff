# SPDX-License-Identifier: Apache-2.0
# Ruff rule D409 (pydocstyle): mismatched section underline length
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d409

import rego.v1

metadata := {
	"id": "RUFF-D409",
	"name": "mismatched section underline length",
	"description": "Section underline should match the length of its name ('<value>')",
	"help_uri": "https://docs.astral.sh/ruff/rules/mismatched-section-underline-length/",
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
	"ruff_code": "D409",
	"ruff_linter": "pydocstyle",
	"ruff_name": "mismatched-section-underline-length",
	"ruff_since": "v0.0.71",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
