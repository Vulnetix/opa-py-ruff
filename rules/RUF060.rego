# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF060 (Ruff-specific rules): in empty collection
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf060

import rego.v1

metadata := {
	"id": "RUFF-RUF060",
	"name": "in empty collection",
	"description": "Unnecessary membership test on empty collection",
	"help_uri": "https://docs.astral.sh/ruff/rules/in-empty-collection/",
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
	"ruff_code": "RUF060",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "in-empty-collection",
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
