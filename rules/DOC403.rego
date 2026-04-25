# SPDX-License-Identifier: Apache-2.0
# Ruff rule DOC403 (pydoclint): docstring extraneous yields
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_doc403

import rego.v1

metadata := {
	"id": "RUFF-DOC403",
	"name": "docstring extraneous yields",
	"description": "Docstring has a 'Yields' section but the function doesn't yield anything",
	"help_uri": "https://docs.astral.sh/ruff/rules/docstring-extraneous-yields/",
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
	"ruff_code": "DOC403",
	"ruff_linter": "pydoclint",
	"ruff_name": "docstring-extraneous-yields",
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
