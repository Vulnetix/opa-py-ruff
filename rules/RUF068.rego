# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF068 (Ruff-specific rules): duplicate entry in dunder all
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf068

import rego.v1

metadata := {
	"id": "RUFF-RUF068",
	"name": "duplicate entry in dunder all",
	"description": "`__all__` contains duplicate entries",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-entry-in-dunder-all/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF068",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "duplicate-entry-in-dunder-all",
	"ruff_since": "0.14.14",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
