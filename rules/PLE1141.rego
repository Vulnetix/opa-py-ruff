# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1141 (Pylint): dict iter missing items
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1141

import rego.v1

metadata := {
	"id": "RUFF-PLE1141",
	"name": "dict iter missing items",
	"description": "Unpacking a dictionary in iteration without calling `.items()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/dict-iter-missing-items/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE1141",
	"ruff_linter": "Pylint",
	"ruff_name": "dict-iter-missing-items",
	"ruff_since": "v0.3.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
