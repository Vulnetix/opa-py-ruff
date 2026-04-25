# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0203 (Pylint): no staticmethod decorator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0203

import rego.v1

metadata := {
	"id": "RUFF-PLR0203",
	"name": "no staticmethod decorator",
	"description": "Static method defined without decorator",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-staticmethod-decorator/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR0203",
	"ruff_linter": "Pylint",
	"ruff_name": "no-staticmethod-decorator",
	"ruff_since": "v0.1.7",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
