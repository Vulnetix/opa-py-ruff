# SPDX-License-Identifier: Apache-2.0
# Ruff rule C402 (flake8-comprehensions): unnecessary generator dict
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c402

import rego.v1

metadata := {
	"id": "RUFF-C402",
	"name": "unnecessary generator dict",
	"description": "Unnecessary generator (rewrite as a dict comprehension)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-generator-dict/",
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
	"ruff_code": "C402",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-generator-dict",
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
