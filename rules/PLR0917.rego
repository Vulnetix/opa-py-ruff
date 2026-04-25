# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0917 (Pylint): too many positional arguments
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0917

import rego.v1

metadata := {
	"id": "RUFF-PLR0917",
	"name": "too many positional arguments",
	"description": "Too many positional arguments (<value>/<value>)",
	"help_uri": "https://docs.astral.sh/ruff/rules/too-many-positional-arguments/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR0917",
	"ruff_linter": "Pylint",
	"ruff_name": "too-many-positional-arguments",
	"ruff_since": "v0.1.7",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
