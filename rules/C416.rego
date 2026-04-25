# SPDX-License-Identifier: Apache-2.0
# Ruff rule C416 (flake8-comprehensions): unnecessary comprehension
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c416

import rego.v1

metadata := {
	"id": "RUFF-C416",
	"name": "unnecessary comprehension",
	"description": "Unnecessary <value> comprehension (rewrite using `<value>()`)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-comprehension/",
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
	"ruff_code": "C416",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-comprehension",
	"ruff_since": "v0.0.73",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
