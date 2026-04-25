# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF034 (Ruff-specific rules): useless if else
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf034

import rego.v1

metadata := {
	"id": "RUFF-RUF034",
	"name": "useless if else",
	"description": "Useless `if`-`else` condition",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-if-else/",
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
	"ruff_code": "RUF034",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "useless-if-else",
	"ruff_since": "0.9.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
