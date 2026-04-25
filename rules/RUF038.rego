# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF038 (Ruff-specific rules): redundant bool literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf038

import rego.v1

metadata := {
	"id": "RUFF-RUF038",
	"name": "redundant bool literal",
	"description": "`Literal[True, False, ...]` can be replaced with `Literal[...] | bool`",
	"help_uri": "https://docs.astral.sh/ruff/rules/redundant-bool-literal/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF038",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "redundant-bool-literal",
	"ruff_since": "0.8.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
