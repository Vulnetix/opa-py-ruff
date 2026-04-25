# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC105 (flake8-async): trio sync call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async105

import rego.v1

metadata := {
	"id": "RUFF-ASYNC105",
	"name": "trio sync call",
	"description": "Call to `<value>` is not immediately awaited",
	"help_uri": "https://docs.astral.sh/ruff/rules/trio-sync-call/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-async", "async"],
	"ruff_code": "ASYNC105",
	"ruff_linter": "flake8-async",
	"ruff_name": "trio-sync-call",
	"ruff_since": "0.5.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
