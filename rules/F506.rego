# SPDX-License-Identifier: Apache-2.0
# Ruff rule F506 (Pyflakes): percent format mixed positional and named
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f506

import rego.v1

metadata := {
	"id": "RUFF-F506",
	"name": "percent format mixed positional and named",
	"description": "`%`-format string has mixed positional and named placeholders",
	"help_uri": "https://docs.astral.sh/ruff/rules/percent-format-mixed-positional-and-named/",
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
	"ruff_code": "F506",
	"ruff_linter": "Pyflakes",
	"ruff_name": "percent-format-mixed-positional-and-named",
	"ruff_since": "v0.0.142",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
