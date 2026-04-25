# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM905 (flake8-simplify): split static string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim905

import rego.v1

metadata := {
	"id": "RUFF-SIM905",
	"name": "split static string",
	"description": "Consider using a list literal instead of `str.{}`",
	"help_uri": "https://docs.astral.sh/ruff/rules/split-static-string/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM905",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "split-static-string",
	"ruff_since": "0.10.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
