# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF047 (Ruff-specific rules): needless else
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf047

import rego.v1

metadata := {
	"id": "RUFF-RUF047",
	"name": "needless else",
	"description": "Empty `else` clause",
	"help_uri": "https://docs.astral.sh/ruff/rules/needless-else/",
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
	"ruff_code": "RUF047",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "needless-else",
	"ruff_since": "0.9.3",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
