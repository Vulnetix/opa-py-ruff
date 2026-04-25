# SPDX-License-Identifier: Apache-2.0
# Ruff rule C408 (flake8-comprehensions): unnecessary collection call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c408

import rego.v1

metadata := {
	"id": "RUFF-C408",
	"name": "unnecessary collection call",
	"description": "Unnecessary `<value>()` call (rewrite as a literal)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-collection-call/",
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
	"ruff_code": "C408",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-collection-call",
	"ruff_since": "v0.0.61",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
