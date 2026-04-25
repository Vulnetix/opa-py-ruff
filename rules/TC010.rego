# SPDX-License-Identifier: Apache-2.0
# Ruff rule TC010 (flake8-type-checking): runtime string union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tc010

import rego.v1

metadata := {
	"id": "RUFF-TC010",
	"name": "runtime string union",
	"description": "Invalid string member in `X | Y`-style union type",
	"help_uri": "https://docs.astral.sh/ruff/rules/runtime-string-union/",
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
	"ruff_code": "TC010",
	"ruff_linter": "flake8-type-checking",
	"ruff_name": "runtime-string-union",
	"ruff_since": "0.8.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
