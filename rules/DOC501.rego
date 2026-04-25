# SPDX-License-Identifier: Apache-2.0
# Ruff rule DOC501 (pydoclint): docstring missing exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_doc501

import rego.v1

metadata := {
	"id": "RUFF-DOC501",
	"name": "docstring missing exception",
	"description": "Raised exception `<value>` missing from docstring",
	"help_uri": "https://docs.astral.sh/ruff/rules/docstring-missing-exception/",
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
	"ruff_code": "DOC501",
	"ruff_linter": "pydoclint",
	"ruff_name": "docstring-missing-exception",
	"ruff_since": "0.5.5",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
