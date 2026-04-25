# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI058 (flake8-pyi): generator return from iter method
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi058

import rego.v1

metadata := {
	"id": "RUFF-PYI058",
	"name": "generator return from iter method",
	"description": "Use `<value>` as the return value for simple `<value>` methods",
	"help_uri": "https://docs.astral.sh/ruff/rules/generator-return-from-iter-method/",
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
	"ruff_code": "PYI058",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "generator-return-from-iter-method",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
