# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI041 (flake8-pyi): redundant numeric union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi041

import rego.v1

metadata := {
	"id": "RUFF-PYI041",
	"name": "redundant numeric union",
	"description": "Use `<value>` instead of `<value> | <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/redundant-numeric-union/",
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
	"ruff_code": "PYI041",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "redundant-numeric-union",
	"ruff_since": "v0.0.279",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
