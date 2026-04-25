# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF049 (Ruff-specific rules): dataclass enum
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf049

import rego.v1

metadata := {
	"id": "RUFF-RUF049",
	"name": "dataclass enum",
	"description": "An enum class should not be decorated with `@dataclass`",
	"help_uri": "https://docs.astral.sh/ruff/rules/dataclass-enum/",
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
	"ruff_code": "RUF049",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "dataclass-enum",
	"ruff_since": "0.12.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
