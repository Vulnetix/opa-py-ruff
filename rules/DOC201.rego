# SPDX-License-Identifier: Apache-2.0
# Ruff rule DOC201 (pydoclint): docstring missing returns
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_doc201

import rego.v1

metadata := {
	"id": "RUFF-DOC201",
	"name": "docstring missing returns",
	"description": "`return` is not documented in docstring",
	"help_uri": "https://docs.astral.sh/ruff/rules/docstring-missing-returns/",
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
	"ruff_code": "DOC201",
	"ruff_linter": "pydoclint",
	"ruff_name": "docstring-missing-returns",
	"ruff_since": "0.5.6",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
