# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF020 (Ruff-specific rules): never union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf020

import rego.v1

metadata := {
	"id": "RUFF-RUF020",
	"name": "never union",
	"description": "`<value> | T` is equivalent to `T`",
	"help_uri": "https://docs.astral.sh/ruff/rules/never-union/",
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
	"ruff_code": "RUF020",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "never-union",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
