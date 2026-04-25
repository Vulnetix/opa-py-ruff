# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF104 (Ruff-specific rules): unmatched suppression comment
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf104

import rego.v1

metadata := {
	"id": "RUFF-RUF104",
	"name": "unmatched suppression comment",
	"description": "Suppression comment without matching `#ruff:enable` comment",
	"help_uri": "https://docs.astral.sh/ruff/rules/unmatched-suppression-comment/",
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
	"ruff_code": "RUF104",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unmatched-suppression-comment",
	"ruff_since": "0.15.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
