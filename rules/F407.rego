# SPDX-License-Identifier: Apache-2.0
# Ruff rule F407 (Pyflakes): future feature not defined
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f407

import rego.v1

metadata := {
	"id": "RUFF-F407",
	"name": "future feature not defined",
	"description": "Future feature `<value>` is not defined",
	"help_uri": "https://docs.astral.sh/ruff/rules/future-feature-not-defined/",
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
	"ruff_code": "F407",
	"ruff_linter": "Pyflakes",
	"ruff_name": "future-feature-not-defined",
	"ruff_since": "v0.0.34",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
