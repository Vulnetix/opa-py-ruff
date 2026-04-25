# SPDX-License-Identifier: Apache-2.0
# Ruff rule F403 (Pyflakes): undefined local with import star
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f403

import rego.v1

metadata := {
	"id": "RUFF-F403",
	"name": "undefined local with import star",
	"description": "`from <value> import *` used; unable to detect undefined names",
	"help_uri": "https://docs.astral.sh/ruff/rules/undefined-local-with-import-star/",
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
	"ruff_code": "F403",
	"ruff_linter": "Pyflakes",
	"ruff_name": "undefined-local-with-import-star",
	"ruff_since": "v0.0.18",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
