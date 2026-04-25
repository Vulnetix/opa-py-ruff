# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF041 (Ruff-specific rules): unnecessary nested literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf041

import rego.v1

metadata := {
	"id": "RUFF-RUF041",
	"name": "unnecessary nested literal",
	"description": "Unnecessary nested `Literal`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-nested-literal/",
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
	"ruff_code": "RUF041",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unnecessary-nested-literal",
	"ruff_since": "0.10.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
