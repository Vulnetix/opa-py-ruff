# SPDX-License-Identifier: Apache-2.0
# Ruff rule B912 (flake8-bugbear): map without explicit strict
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b912

import rego.v1

metadata := {
	"id": "RUFF-B912",
	"name": "map without explicit strict",
	"description": "`map()` without an explicit `strict=` parameter",
	"help_uri": "https://docs.astral.sh/ruff/rules/map-without-explicit-strict/",
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
	"ruff_code": "B912",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "map-without-explicit-strict",
	"ruff_since": "0.15.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
