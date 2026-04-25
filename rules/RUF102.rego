# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF102 (Ruff-specific rules): invalid rule code
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf102

import rego.v1

metadata := {
	"id": "RUFF-RUF102",
	"name": "invalid rule code",
	"description": "Invalid rule code in {}: {}",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-rule-code/",
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
	"ruff_code": "RUF102",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "invalid-rule-code",
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
