# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB122 (refurb): for loop writes
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb122

import rego.v1

metadata := {
	"id": "RUFF-FURB122",
	"name": "for loop writes",
	"description": "Use of `{}.write` in a for loop",
	"help_uri": "https://docs.astral.sh/ruff/rules/for-loop-writes/",
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
	"ruff_code": "FURB122",
	"ruff_linter": "refurb",
	"ruff_name": "for-loop-writes",
	"ruff_since": "0.12.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
