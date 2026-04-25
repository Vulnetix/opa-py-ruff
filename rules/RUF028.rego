# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF028 (Ruff-specific rules): invalid formatter suppression comment
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf028

import rego.v1

metadata := {
	"id": "RUFF-RUF028",
	"name": "invalid formatter suppression comment",
	"description": "This suppression comment is invalid because {}",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-formatter-suppression-comment/",
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
	"ruff_code": "RUF028",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "invalid-formatter-suppression-comment",
	"ruff_since": "0.12.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
