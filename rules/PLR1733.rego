# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR1733 (Pylint): unnecessary dict index lookup
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr1733

import rego.v1

metadata := {
	"id": "RUFF-PLR1733",
	"name": "unnecessary dict index lookup",
	"description": "Unnecessary lookup of dictionary value by key",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-dict-index-lookup/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR1733",
	"ruff_linter": "Pylint",
	"ruff_name": "unnecessary-dict-index-lookup",
	"ruff_since": "0.12.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
