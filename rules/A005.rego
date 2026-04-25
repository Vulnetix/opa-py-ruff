# SPDX-License-Identifier: Apache-2.0
# Ruff rule A005 (flake8-builtins): stdlib module shadowing
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_a005

import rego.v1

metadata := {
	"id": "RUFF-A005",
	"name": "stdlib module shadowing",
	"description": "Module `<value>` shadows a Python standard-library module",
	"help_uri": "https://docs.astral.sh/ruff/rules/stdlib-module-shadowing/",
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
	"ruff_code": "A005",
	"ruff_linter": "flake8-builtins",
	"ruff_name": "stdlib-module-shadowing",
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
