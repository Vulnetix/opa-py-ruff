# SPDX-License-Identifier: Apache-2.0
# Ruff rule D206 (pydocstyle): docstring tab indentation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d206

import rego.v1

metadata := {
	"id": "RUFF-D206",
	"name": "docstring tab indentation",
	"description": "Docstring should be indented with spaces, not tabs",
	"help_uri": "https://docs.astral.sh/ruff/rules/docstring-tab-indentation/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pydocstyle", "d"],
	"ruff_code": "D206",
	"ruff_linter": "pydocstyle",
	"ruff_name": "docstring-tab-indentation",
	"ruff_since": "v0.0.75",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
