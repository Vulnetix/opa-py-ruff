# SPDX-License-Identifier: Apache-2.0
# Ruff rule DOC402 (pydoclint): docstring missing yields
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_doc402

import rego.v1

metadata := {
	"id": "RUFF-DOC402",
	"name": "docstring missing yields",
	"description": "`yield` is not documented in docstring",
	"help_uri": "https://docs.astral.sh/ruff/rules/docstring-missing-yields/",
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
	"ruff_code": "DOC402",
	"ruff_linter": "pydoclint",
	"ruff_name": "docstring-missing-yields",
	"ruff_since": "0.5.7",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
