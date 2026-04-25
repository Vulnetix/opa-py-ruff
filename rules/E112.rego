# SPDX-License-Identifier: Apache-2.0
# Ruff rule E112 (pycodestyle): no indented block
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e112

import rego.v1

metadata := {
	"id": "RUFF-E112",
	"name": "no indented block",
	"description": "Expected an indented block",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-indented-block/",
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
	"ruff_code": "E112",
	"ruff_linter": "pycodestyle",
	"ruff_name": "no-indented-block",
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
