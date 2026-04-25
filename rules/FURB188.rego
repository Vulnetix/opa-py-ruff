# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB188 (refurb): slice to remove prefix or suffix
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb188

import rego.v1

metadata := {
	"id": "RUFF-FURB188",
	"name": "slice to remove prefix or suffix",
	"description": "Prefer `str.removeprefix()` over conditionally replacing with slice.",
	"help_uri": "https://docs.astral.sh/ruff/rules/slice-to-remove-prefix-or-suffix/",
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
	"ruff_code": "FURB188",
	"ruff_linter": "refurb",
	"ruff_name": "slice-to-remove-prefix-or-suffix",
	"ruff_since": "0.9.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
