# SPDX-License-Identifier: Apache-2.0
# Ruff rule ICN003 (flake8-import-conventions): banned import from
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_icn003

import rego.v1

metadata := {
	"id": "RUFF-ICN003",
	"name": "banned import from",
	"description": "Members of `<value>` should not be imported explicitly",
	"help_uri": "https://docs.astral.sh/ruff/rules/banned-import-from/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-import-conventions", "icn"],
	"ruff_code": "ICN003",
	"ruff_linter": "flake8-import-conventions",
	"ruff_name": "banned-import-from",
	"ruff_since": "v0.0.263",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
