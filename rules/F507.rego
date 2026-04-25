# SPDX-License-Identifier: Apache-2.0
# Ruff rule F507 (Pyflakes): percent format positional count mismatch
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f507

import rego.v1

metadata := {
	"id": "RUFF-F507",
	"name": "percent format positional count mismatch",
	"description": "`%`-format string has <value> placeholder(s) but <value> substitution(s)",
	"help_uri": "https://docs.astral.sh/ruff/rules/percent-format-positional-count-mismatch/",
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
	"ruff_code": "F507",
	"ruff_linter": "Pyflakes",
	"ruff_name": "percent-format-positional-count-mismatch",
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
