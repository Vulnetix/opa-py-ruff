# SPDX-License-Identifier: Apache-2.0
# Ruff rule F402 (Pyflakes): import shadowed by loop var
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f402

import rego.v1

metadata := {
	"id": "RUFF-F402",
	"name": "import shadowed by loop var",
	"description": "Import `<value>` from <value> shadowed by loop variable",
	"help_uri": "https://docs.astral.sh/ruff/rules/import-shadowed-by-loop-var/",
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
	"ruff_code": "F402",
	"ruff_linter": "Pyflakes",
	"ruff_name": "import-shadowed-by-loop-var",
	"ruff_since": "v0.0.44",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
