# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF031 (Ruff-specific rules): incorrectly parenthesized tuple in subscript
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf031

import rego.v1

metadata := {
	"id": "RUFF-RUF031",
	"name": "incorrectly parenthesized tuple in subscript",
	"description": "Use parentheses for tuples in subscripts",
	"help_uri": "https://docs.astral.sh/ruff/rules/incorrectly-parenthesized-tuple-in-subscript/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF031",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "incorrectly-parenthesized-tuple-in-subscript",
	"ruff_since": "0.5.7",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
