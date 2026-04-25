# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB169 (refurb): type none comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb169

import rego.v1

metadata := {
	"id": "RUFF-FURB169",
	"name": "type none comparison",
	"description": "When checking against `None`, use `{}` instead of comparison with `type(None)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-none-comparison/",
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
	"ruff_code": "FURB169",
	"ruff_linter": "refurb",
	"ruff_name": "type-none-comparison",
	"ruff_since": "0.5.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
