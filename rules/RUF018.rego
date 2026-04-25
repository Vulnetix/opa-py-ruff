# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF018 (Ruff-specific rules): assignment in assert
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf018

import rego.v1

metadata := {
	"id": "RUFF-RUF018",
	"name": "assignment in assert",
	"description": "Avoid assignment expressions in `assert` statements",
	"help_uri": "https://docs.astral.sh/ruff/rules/assignment-in-assert/",
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
	"ruff_code": "RUF018",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "assignment-in-assert",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
