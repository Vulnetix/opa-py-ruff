# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF057 (Ruff-specific rules): unnecessary round
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf057

import rego.v1

metadata := {
	"id": "RUFF-RUF057",
	"name": "unnecessary round",
	"description": "Value being rounded is already an integer",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-round/",
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
	"ruff_code": "RUF057",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unnecessary-round",
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
