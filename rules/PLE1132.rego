# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1132 (Pylint): repeated keyword argument
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1132

import rego.v1

metadata := {
	"id": "RUFF-PLE1132",
	"name": "repeated keyword argument",
	"description": "Repeated keyword argument: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/repeated-keyword-argument/",
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
	"ruff_code": "PLE1132",
	"ruff_linter": "Pylint",
	"ruff_name": "repeated-keyword-argument",
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
