# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF063 (Ruff-specific rules): access annotations from class dict
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf063

import rego.v1

metadata := {
	"id": "RUFF-RUF063",
	"name": "access annotations from class dict",
	"description": "Use `<value>` instead of `__dict__` access",
	"help_uri": "https://docs.astral.sh/ruff/rules/access-annotations-from-class-dict/",
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
	"ruff_code": "RUF063",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "access-annotations-from-class-dict",
	"ruff_since": "0.12.1",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
