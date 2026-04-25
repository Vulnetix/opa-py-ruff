# SPDX-License-Identifier: Apache-2.0
# Ruff rule C411 (flake8-comprehensions): unnecessary list call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c411

import rego.v1

metadata := {
	"id": "RUFF-C411",
	"name": "unnecessary list call",
	"description": "Unnecessary `list()` call (remove the outer call to `list()`)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-list-call/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-comprehensions", "c"],
	"ruff_code": "C411",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-list-call",
	"ruff_since": "v0.0.73",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
