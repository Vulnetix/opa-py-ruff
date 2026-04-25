# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR1708 (Pylint): stop iteration return
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr1708

import rego.v1

metadata := {
	"id": "RUFF-PLR1708",
	"name": "stop iteration return",
	"description": "Explicit `raise StopIteration` in generator",
	"help_uri": "https://docs.astral.sh/ruff/rules/stop-iteration-return/",
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
	"ruff_code": "PLR1708",
	"ruff_linter": "Pylint",
	"ruff_name": "stop-iteration-return",
	"ruff_since": "0.14.3",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
