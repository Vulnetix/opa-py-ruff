# SPDX-License-Identifier: Apache-2.0
# Ruff rule ICN002 (flake8-import-conventions): banned import alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_icn002

import rego.v1

metadata := {
	"id": "RUFF-ICN002",
	"name": "banned import alias",
	"description": "`<value>` should not be imported as `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/banned-import-alias/",
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
	"ruff_code": "ICN002",
	"ruff_linter": "flake8-import-conventions",
	"ruff_name": "banned-import-alias",
	"ruff_since": "v0.0.262",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
