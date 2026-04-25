# SPDX-License-Identifier: Apache-2.0
# Ruff rule TC008 (flake8-type-checking): quoted type alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tc008

import rego.v1

metadata := {
	"id": "RUFF-TC008",
	"name": "quoted type alias",
	"description": "Remove quotes from type alias",
	"help_uri": "https://docs.astral.sh/ruff/rules/quoted-type-alias/",
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
	"ruff_code": "TC008",
	"ruff_linter": "flake8-type-checking",
	"ruff_name": "quoted-type-alias",
	"ruff_since": "0.8.1",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
