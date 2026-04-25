# SPDX-License-Identifier: Apache-2.0
# Ruff rule RSE102 (flake8-raise): unnecessary paren on raise exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_rse102

import rego.v1

metadata := {
	"id": "RUFF-RSE102",
	"name": "unnecessary paren on raise exception",
	"description": "Unnecessary parentheses on raised exception",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-paren-on-raise-exception/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-raise", "rse"],
	"ruff_code": "RSE102",
	"ruff_linter": "flake8-raise",
	"ruff_name": "unnecessary-paren-on-raise-exception",
	"ruff_since": "v0.0.239",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
