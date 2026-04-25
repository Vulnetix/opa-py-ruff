# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB142 (refurb): for loop set mutations
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb142

import rego.v1

metadata := {
	"id": "RUFF-FURB142",
	"name": "for loop set mutations",
	"description": "Use of `set.{}()` in a for loop",
	"help_uri": "https://docs.astral.sh/ruff/rules/for-loop-set-mutations/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB142",
	"ruff_linter": "refurb",
	"ruff_name": "for-loop-set-mutations",
	"ruff_since": "v0.3.5",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
