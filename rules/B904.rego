# SPDX-License-Identifier: Apache-2.0
# Ruff rule B904 (flake8-bugbear): raise without from inside except
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b904

import rego.v1

metadata := {
	"id": "RUFF-B904",
	"name": "raise without from inside except",
	"description": "Within an `except*` clause, raise exceptions with `raise ... from err` or `raise ... from None` to distinguish them from errors in exception handling",
	"help_uri": "https://docs.astral.sh/ruff/rules/raise-without-from-inside-except/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B904",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "raise-without-from-inside-except",
	"ruff_since": "v0.0.138",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
