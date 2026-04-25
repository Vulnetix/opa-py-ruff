# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI012 (flake8-pyi): pass in class body
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi012

import rego.v1

metadata := {
	"id": "RUFF-PYI012",
	"name": "pass in class body",
	"description": "Class body must not contain `pass`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pass-in-class-body/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI012",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "pass-in-class-body",
	"ruff_since": "v0.0.260",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
