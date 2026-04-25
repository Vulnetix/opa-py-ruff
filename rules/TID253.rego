# SPDX-License-Identifier: Apache-2.0
# Ruff rule TID253 (flake8-tidy-imports): banned module level imports
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tid253

import rego.v1

metadata := {
	"id": "RUFF-TID253",
	"name": "banned module level imports",
	"description": "`<value>` is banned at the module level",
	"help_uri": "https://docs.astral.sh/ruff/rules/banned-module-level-imports/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-tidy-imports", "tid"],
	"ruff_code": "TID253",
	"ruff_linter": "flake8-tidy-imports",
	"ruff_name": "banned-module-level-imports",
	"ruff_since": "v0.0.285",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
