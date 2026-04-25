# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0914 (Pylint): too many locals
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0914

import rego.v1

metadata := {
	"id": "RUFF-PLR0914",
	"name": "too many locals",
	"description": "Too many local variables (<value>/<value>)",
	"help_uri": "https://docs.astral.sh/ruff/rules/too-many-locals/",
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
	"ruff_code": "PLR0914",
	"ruff_linter": "Pylint",
	"ruff_name": "too-many-locals",
	"ruff_since": "v0.1.9",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
