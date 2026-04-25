# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY203 (tryceratops): useless try except
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try203

import rego.v1

metadata := {
	"id": "RUFF-TRY203",
	"name": "useless try except",
	"description": "Remove exception handler; error is immediately re-raised",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-try-except/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "tryceratops", "try"],
	"ruff_code": "TRY203",
	"ruff_linter": "tryceratops",
	"ruff_name": "useless-try-except",
	"ruff_since": "0.7.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
