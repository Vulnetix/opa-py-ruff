# SPDX-License-Identifier: Apache-2.0
# Ruff rule E202 (pycodestyle): whitespace before close bracket
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e202

import rego.v1

metadata := {
	"id": "RUFF-E202",
	"name": "whitespace before close bracket",
	"description": "Whitespace before '<value>'",
	"help_uri": "https://docs.astral.sh/ruff/rules/whitespace-before-close-bracket/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E202",
	"ruff_linter": "pycodestyle",
	"ruff_name": "whitespace-before-close-bracket",
	"ruff_since": "v0.0.269",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
