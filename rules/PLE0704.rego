# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0704 (Pylint): misplaced bare raise
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0704

import rego.v1

metadata := {
	"id": "RUFF-PLE0704",
	"name": "misplaced bare raise",
	"description": "Bare `raise` statement is not inside an exception handler",
	"help_uri": "https://docs.astral.sh/ruff/rules/misplaced-bare-raise/",
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
	"ruff_code": "PLE0704",
	"ruff_linter": "Pylint",
	"ruff_name": "misplaced-bare-raise",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
