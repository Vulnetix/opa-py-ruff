# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0303 (Pylint): invalid length return type
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0303

import rego.v1

metadata := {
	"id": "RUFF-PLE0303",
	"name": "invalid length return type",
	"description": "`__len__` does not return a non-negative integer",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-length-return-type/",
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
	"ruff_code": "PLE0303",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-length-return-type",
	"ruff_since": "0.6.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
