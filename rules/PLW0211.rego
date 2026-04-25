# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0211 (Pylint): bad staticmethod argument
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0211

import rego.v1

metadata := {
	"id": "RUFF-PLW0211",
	"name": "bad staticmethod argument",
	"description": "First argument of a static method should not be named `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-staticmethod-argument/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0211",
	"ruff_linter": "Pylint",
	"ruff_name": "bad-staticmethod-argument",
	"ruff_since": "0.6.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
