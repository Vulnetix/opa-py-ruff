# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1520 (Pylint): singledispatchmethod function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1520

import rego.v1

metadata := {
	"id": "RUFF-PLE1520",
	"name": "singledispatchmethod function",
	"description": "`@singledispatchmethod` decorator should not be used on non-method functions",
	"help_uri": "https://docs.astral.sh/ruff/rules/singledispatchmethod-function/",
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
	"ruff_code": "PLE1520",
	"ruff_linter": "Pylint",
	"ruff_name": "singledispatchmethod-function",
	"ruff_since": "0.6.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
