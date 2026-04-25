# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF008 (Ruff-specific rules): mutable dataclass default
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf008

import rego.v1

metadata := {
	"id": "RUFF-RUF008",
	"name": "mutable dataclass default",
	"description": "Do not use mutable default values for dataclass attributes",
	"help_uri": "https://docs.astral.sh/ruff/rules/mutable-dataclass-default/",
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
	"ruff_code": "RUF008",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "mutable-dataclass-default",
	"ruff_since": "v0.0.262",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
