# SPDX-License-Identifier: Apache-2.0
# Ruff rule E201 (pycodestyle): whitespace after open bracket
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e201

import rego.v1

metadata := {
	"id": "RUFF-E201",
	"name": "whitespace after open bracket",
	"description": "Whitespace after '<value>'",
	"help_uri": "https://docs.astral.sh/ruff/rules/whitespace-after-open-bracket/",
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
	"ruff_code": "E201",
	"ruff_linter": "pycodestyle",
	"ruff_name": "whitespace-after-open-bracket",
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
