# SPDX-License-Identifier: Apache-2.0
# Ruff rule C414 (flake8-comprehensions): unnecessary double cast or process
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c414

import rego.v1

metadata := {
	"id": "RUFF-C414",
	"name": "unnecessary double cast or process",
	"description": "Unnecessary `<value>()` call within `<value>()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-double-cast-or-process/",
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
	"ruff_code": "C414",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-double-cast-or-process",
	"ruff_since": "v0.0.70",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
