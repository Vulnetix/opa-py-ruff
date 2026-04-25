# SPDX-License-Identifier: Apache-2.0
# Ruff rule B901 (flake8-bugbear): return in generator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b901

import rego.v1

metadata := {
	"id": "RUFF-B901",
	"name": "return in generator",
	"description": "Using `yield` and `return <value>` in a generator function can lead to confusing behavior",
	"help_uri": "https://docs.astral.sh/ruff/rules/return-in-generator/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B901",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "return-in-generator",
	"ruff_since": "v0.4.8",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
