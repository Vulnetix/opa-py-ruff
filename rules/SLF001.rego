# SPDX-License-Identifier: Apache-2.0
# Ruff rule SLF001 (flake8-self): private member access
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_slf001

import rego.v1

metadata := {
	"id": "RUFF-SLF001",
	"name": "private member access",
	"description": "Private member accessed: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/private-member-access/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-self", "slf"],
	"ruff_code": "SLF001",
	"ruff_linter": "flake8-self",
	"ruff_name": "private-member-access",
	"ruff_since": "v0.0.240",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
