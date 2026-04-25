# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0643 (Pylint): potential index error
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0643

import rego.v1

metadata := {
	"id": "RUFF-PLE0643",
	"name": "potential index error",
	"description": "Expression is likely to raise `IndexError`",
	"help_uri": "https://docs.astral.sh/ruff/rules/potential-index-error/",
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
	"ruff_code": "PLE0643",
	"ruff_linter": "Pylint",
	"ruff_name": "potential-index-error",
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
