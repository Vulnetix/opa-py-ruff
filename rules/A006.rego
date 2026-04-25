# SPDX-License-Identifier: Apache-2.0
# Ruff rule A006 (flake8-builtins): builtin lambda argument shadowing
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_a006

import rego.v1

metadata := {
	"id": "RUFF-A006",
	"name": "builtin lambda argument shadowing",
	"description": "Lambda argument `<value>` is shadowing a Python builtin",
	"help_uri": "https://docs.astral.sh/ruff/rules/builtin-lambda-argument-shadowing/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-builtins", "a"],
	"ruff_code": "A006",
	"ruff_linter": "flake8-builtins",
	"ruff_name": "builtin-lambda-argument-shadowing",
	"ruff_since": "0.9.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
