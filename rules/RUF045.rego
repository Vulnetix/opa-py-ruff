# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF045 (Ruff-specific rules): implicit class var in dataclass
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf045

import rego.v1

metadata := {
	"id": "RUFF-RUF045",
	"name": "implicit class var in dataclass",
	"description": "Assignment without annotation found in dataclass body",
	"help_uri": "https://docs.astral.sh/ruff/rules/implicit-class-var-in-dataclass/",
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
	"ruff_code": "RUF045",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "implicit-class-var-in-dataclass",
	"ruff_since": "0.9.7",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
