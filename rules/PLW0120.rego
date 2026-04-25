# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0120 (Pylint): useless else on loop
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0120

import rego.v1

metadata := {
	"id": "RUFF-PLW0120",
	"name": "useless else on loop",
	"description": "`else` clause on loop without a `break` statement; remove the `else` and dedent its contents",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-else-on-loop/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0120",
	"ruff_linter": "Pylint",
	"ruff_name": "useless-else-on-loop",
	"ruff_since": "v0.0.156",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
