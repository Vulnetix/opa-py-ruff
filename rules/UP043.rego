# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP043 (pyupgrade): unnecessary default type args
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up043

import rego.v1

metadata := {
	"id": "RUFF-UP043",
	"name": "unnecessary default type args",
	"description": "Unnecessary default type arguments",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-default-type-args/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP043",
	"ruff_linter": "pyupgrade",
	"ruff_name": "unnecessary-default-type-args",
	"ruff_since": "0.8.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
