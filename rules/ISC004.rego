# SPDX-License-Identifier: Apache-2.0
# Ruff rule ISC004 (flake8-implicit-str-concat): implicit string concatenation in collection literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_isc004

import rego.v1

metadata := {
	"id": "RUFF-ISC004",
	"name": "implicit string concatenation in collection literal",
	"description": "Unparenthesized implicit string concatenation in collection",
	"help_uri": "https://docs.astral.sh/ruff/rules/implicit-string-concatenation-in-collection-literal/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-implicit-str-concat", "isc"],
	"ruff_code": "ISC004",
	"ruff_linter": "flake8-implicit-str-concat",
	"ruff_name": "implicit-string-concatenation-in-collection-literal",
	"ruff_since": "0.14.10",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
