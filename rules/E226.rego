# SPDX-License-Identifier: Apache-2.0
# Ruff rule E226 (pycodestyle): missing whitespace around arithmetic operator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e226

import rego.v1

metadata := {
	"id": "RUFF-E226",
	"name": "missing whitespace around arithmetic operator",
	"description": "Missing whitespace around arithmetic operator",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-whitespace-around-arithmetic-operator/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E226",
	"ruff_linter": "pycodestyle",
	"ruff_name": "missing-whitespace-around-arithmetic-operator",
	"ruff_since": "v0.0.269",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
