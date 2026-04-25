# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP013 (pyupgrade): convert typed dict functional to class
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up013

import rego.v1

metadata := {
	"id": "RUFF-UP013",
	"name": "convert typed dict functional to class",
	"description": "Convert `<value>` from `TypedDict` functional to class syntax",
	"help_uri": "https://docs.astral.sh/ruff/rules/convert-typed-dict-functional-to-class/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP013",
	"ruff_linter": "pyupgrade",
	"ruff_name": "convert-typed-dict-functional-to-class",
	"ruff_since": "v0.0.155",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
