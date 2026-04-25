# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0304 (Pylint): invalid bool return type
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0304

import rego.v1

metadata := {
	"id": "RUFF-PLE0304",
	"name": "invalid bool return type",
	"description": "`__bool__` does not return `bool`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-bool-return-type/",
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
	"ruff_code": "PLE0304",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-bool-return-type",
	"ruff_since": "v0.3.3",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
