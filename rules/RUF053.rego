# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF053 (Ruff-specific rules): class with mixed type vars
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf053

import rego.v1

metadata := {
	"id": "RUFF-RUF053",
	"name": "class with mixed type vars",
	"description": "Class with type parameter list inherits from `Generic`",
	"help_uri": "https://docs.astral.sh/ruff/rules/class-with-mixed-type-vars/",
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
	"ruff_code": "RUF053",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "class-with-mixed-type-vars",
	"ruff_since": "0.12.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
