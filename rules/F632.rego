# SPDX-License-Identifier: Apache-2.0
# Ruff rule F632 (Pyflakes): is literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f632

import rego.v1

metadata := {
	"id": "RUFF-F632",
	"name": "is literal",
	"description": "Use `==` to compare constant literals",
	"help_uri": "https://docs.astral.sh/ruff/rules/is-literal/",
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
	"ruff_code": "F632",
	"ruff_linter": "Pyflakes",
	"ruff_name": "is-literal",
	"ruff_since": "v0.0.39",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
