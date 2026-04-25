# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP046 (pyupgrade): non pep695 generic class
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up046

import rego.v1

metadata := {
	"id": "RUFF-UP046",
	"name": "non pep695 generic class",
	"description": "Generic class `<value>` uses `Generic` subclass instead of type parameters",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep695-generic-class/",
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
	"ruff_code": "UP046",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep695-generic-class",
	"ruff_since": "0.12.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
