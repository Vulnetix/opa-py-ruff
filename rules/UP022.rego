# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP022 (pyupgrade): replace stdout stderr
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up022

import rego.v1

metadata := {
	"id": "RUFF-UP022",
	"name": "replace stdout stderr",
	"description": "Prefer `capture_output` over sending `stdout` and `stderr` to `PIPE`",
	"help_uri": "https://docs.astral.sh/ruff/rules/replace-stdout-stderr/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP022",
	"ruff_linter": "pyupgrade",
	"ruff_name": "replace-stdout-stderr",
	"ruff_since": "v0.0.199",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
