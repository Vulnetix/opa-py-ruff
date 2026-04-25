# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF065 (Ruff-specific rules): logging eager conversion
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf065

import rego.v1

metadata := {
	"id": "RUFF-RUF065",
	"name": "logging eager conversion",
	"description": "Unnecessary `oct()` conversion when formatting with `%s`. Use `%#o` instead of `%s`",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-eager-conversion/",
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
	"ruff_code": "RUF065",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "logging-eager-conversion",
	"ruff_since": "0.13.2",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
