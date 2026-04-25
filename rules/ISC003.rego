# SPDX-License-Identifier: Apache-2.0
# Ruff rule ISC003 (flake8-implicit-str-concat): explicit string concatenation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_isc003

import rego.v1

metadata := {
	"id": "RUFF-ISC003",
	"name": "explicit string concatenation",
	"description": "Explicitly concatenated string should be implicitly concatenated",
	"help_uri": "https://docs.astral.sh/ruff/rules/explicit-string-concatenation/",
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
	"ruff_code": "ISC003",
	"ruff_linter": "flake8-implicit-str-concat",
	"ruff_name": "explicit-string-concatenation",
	"ruff_since": "v0.0.201",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
