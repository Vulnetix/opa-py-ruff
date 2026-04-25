# SPDX-License-Identifier: Apache-2.0
# Ruff rule C415 (flake8-comprehensions): unnecessary subscript reversal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c415

import rego.v1

metadata := {
	"id": "RUFF-C415",
	"name": "unnecessary subscript reversal",
	"description": "Unnecessary subscript reversal of iterable within `<value>()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-subscript-reversal/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-comprehensions", "c"],
	"ruff_code": "C415",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-subscript-reversal",
	"ruff_since": "v0.0.64",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
