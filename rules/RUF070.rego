# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF070 (Ruff-specific rules): unnecessary assign before yield
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf070

import rego.v1

metadata := {
	"id": "RUFF-RUF070",
	"name": "unnecessary assign before yield",
	"description": "Unnecessary assignment to `<value>` before `yield from` statement",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-assign-before-yield/",
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
	"ruff_code": "RUF070",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unnecessary-assign-before-yield",
	"ruff_since": "0.15.3",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
