# SPDX-License-Identifier: Apache-2.0
# Ruff rule F522 (Pyflakes): string dot format extra named arguments
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f522

import rego.v1

metadata := {
	"id": "RUFF-F522",
	"name": "string dot format extra named arguments",
	"description": "`.format` call has unused named argument(s): <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/string-dot-format-extra-named-arguments/",
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
	"ruff_code": "F522",
	"ruff_linter": "Pyflakes",
	"ruff_name": "string-dot-format-extra-named-arguments",
	"ruff_since": "v0.0.139",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
