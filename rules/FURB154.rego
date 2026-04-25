# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB154 (refurb): repeated global
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb154

import rego.v1

metadata := {
	"id": "RUFF-FURB154",
	"name": "repeated global",
	"description": "Use of repeated consecutive `{}`",
	"help_uri": "https://docs.astral.sh/ruff/rules/repeated-global/",
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
	"ruff_code": "FURB154",
	"ruff_linter": "refurb",
	"ruff_name": "repeated-global",
	"ruff_since": "v0.4.9",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
