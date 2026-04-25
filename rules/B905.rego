# SPDX-License-Identifier: Apache-2.0
# Ruff rule B905 (flake8-bugbear): zip without explicit strict
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b905

import rego.v1

metadata := {
	"id": "RUFF-B905",
	"name": "zip without explicit strict",
	"description": "`zip()` without an explicit `strict=` parameter",
	"help_uri": "https://docs.astral.sh/ruff/rules/zip-without-explicit-strict/",
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
	"ruff_code": "B905",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "zip-without-explicit-strict",
	"ruff_since": "v0.0.167",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
