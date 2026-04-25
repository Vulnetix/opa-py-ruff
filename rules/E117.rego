# SPDX-License-Identifier: Apache-2.0
# Ruff rule E117 (pycodestyle): over indented
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e117

import rego.v1

metadata := {
	"id": "RUFF-E117",
	"name": "over indented",
	"description": "Over-indented (comment)",
	"help_uri": "https://docs.astral.sh/ruff/rules/over-indented/",
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
	"ruff_code": "E117",
	"ruff_linter": "pycodestyle",
	"ruff_name": "over-indented",
	"ruff_since": "v0.0.269",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
