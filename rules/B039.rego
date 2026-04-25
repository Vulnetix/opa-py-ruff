# SPDX-License-Identifier: Apache-2.0
# Ruff rule B039 (flake8-bugbear): mutable contextvar default
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b039

import rego.v1

metadata := {
	"id": "RUFF-B039",
	"name": "mutable contextvar default",
	"description": "Do not use mutable data structures for `ContextVar` defaults",
	"help_uri": "https://docs.astral.sh/ruff/rules/mutable-contextvar-default/",
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
	"ruff_code": "B039",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "mutable-contextvar-default",
	"ruff_since": "0.8.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
