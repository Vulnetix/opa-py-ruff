# SPDX-License-Identifier: Apache-2.0
# Ruff rule C404 (flake8-comprehensions): unnecessary list comprehension dict
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c404

import rego.v1

metadata := {
	"id": "RUFF-C404",
	"name": "unnecessary list comprehension dict",
	"description": "Unnecessary list comprehension (rewrite as a dict comprehension)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-list-comprehension-dict/",
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
	"ruff_code": "C404",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-list-comprehension-dict",
	"ruff_since": "v0.0.58",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
