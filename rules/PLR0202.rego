# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0202 (Pylint): no classmethod decorator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0202

import rego.v1

metadata := {
	"id": "RUFF-PLR0202",
	"name": "no classmethod decorator",
	"description": "Class method defined without decorator",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-classmethod-decorator/",
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
	"ruff_code": "PLR0202",
	"ruff_linter": "Pylint",
	"ruff_name": "no-classmethod-decorator",
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
