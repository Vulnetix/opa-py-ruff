# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI013 (flake8-pyi): ellipsis in non empty class body
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi013

import rego.v1

metadata := {
	"id": "RUFF-PYI013",
	"name": "ellipsis in non empty class body",
	"description": "Non-empty class body must not contain `...`",
	"help_uri": "https://docs.astral.sh/ruff/rules/ellipsis-in-non-empty-class-body/",
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
	"ruff_code": "PYI013",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "ellipsis-in-non-empty-class-body",
	"ruff_since": "v0.0.270",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
