# SPDX-License-Identifier: Apache-2.0
# Ruff rule F707 (Pyflakes): default except not last
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f707

import rego.v1

metadata := {
	"id": "RUFF-F707",
	"name": "default except not last",
	"description": "An `except` block as not the last exception handler",
	"help_uri": "https://docs.astral.sh/ruff/rules/default-except-not-last/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyflakes", "f"],
	"ruff_code": "F707",
	"ruff_linter": "Pyflakes",
	"ruff_name": "default-except-not-last",
	"ruff_since": "v0.0.28",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
