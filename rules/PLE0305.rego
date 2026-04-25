# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0305 (Pylint): invalid index return type
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0305

import rego.v1

metadata := {
	"id": "RUFF-PLE0305",
	"name": "invalid index return type",
	"description": "`__index__` does not return an integer",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-index-return-type/",
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
	"ruff_code": "PLE0305",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-index-return-type",
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
