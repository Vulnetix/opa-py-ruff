# SPDX-License-Identifier: Apache-2.0
# Ruff rule DOC102 (pydoclint): docstring extraneous parameter
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_doc102

import rego.v1

metadata := {
	"id": "RUFF-DOC102",
	"name": "docstring extraneous parameter",
	"description": "Documented parameter `<value>` is not in the function's signature",
	"help_uri": "https://docs.astral.sh/ruff/rules/docstring-extraneous-parameter/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pydoclint", "doc"],
	"ruff_code": "DOC102",
	"ruff_linter": "pydoclint",
	"ruff_name": "docstring-extraneous-parameter",
	"ruff_since": "0.14.1",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
