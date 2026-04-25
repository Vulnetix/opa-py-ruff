# SPDX-License-Identifier: Apache-2.0
# Ruff rule N807 (pep8-naming): dunder function name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n807

import rego.v1

metadata := {
	"id": "RUFF-N807",
	"name": "dunder function name",
	"description": "Function name should not start and end with `__`",
	"help_uri": "https://docs.astral.sh/ruff/rules/dunder-function-name/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pep8-naming", "n"],
	"ruff_code": "N807",
	"ruff_linter": "pep8-naming",
	"ruff_name": "dunder-function-name",
	"ruff_since": "v0.0.82",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
