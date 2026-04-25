# SPDX-License-Identifier: Apache-2.0
# Ruff rule E224 (pycodestyle): tab after operator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e224

import rego.v1

metadata := {
	"id": "RUFF-E224",
	"name": "tab after operator",
	"description": "Tab after operator",
	"help_uri": "https://docs.astral.sh/ruff/rules/tab-after-operator/",
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
	"ruff_code": "E224",
	"ruff_linter": "pycodestyle",
	"ruff_name": "tab-after-operator",
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
