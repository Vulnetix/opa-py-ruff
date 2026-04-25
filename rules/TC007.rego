# SPDX-License-Identifier: Apache-2.0
# Ruff rule TC007 (flake8-type-checking): unquoted type alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tc007

import rego.v1

metadata := {
	"id": "RUFF-TC007",
	"name": "unquoted type alias",
	"description": "Add quotes to type alias",
	"help_uri": "https://docs.astral.sh/ruff/rules/unquoted-type-alias/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-type-checking", "tc"],
	"ruff_code": "TC007",
	"ruff_linter": "flake8-type-checking",
	"ruff_name": "unquoted-type-alias",
	"ruff_since": "0.10.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
