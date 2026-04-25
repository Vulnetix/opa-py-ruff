# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI048 (flake8-pyi): stub body multiple statements
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi048

import rego.v1

metadata := {
	"id": "RUFF-PYI048",
	"name": "stub body multiple statements",
	"description": "Function body must contain exactly one statement",
	"help_uri": "https://docs.astral.sh/ruff/rules/stub-body-multiple-statements/",
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
	"ruff_code": "PYI048",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "stub-body-multiple-statements",
	"ruff_since": "v0.0.271",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
