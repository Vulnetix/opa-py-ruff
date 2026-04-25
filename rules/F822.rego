# SPDX-License-Identifier: Apache-2.0
# Ruff rule F822 (Pyflakes): undefined export
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f822

import rego.v1

metadata := {
	"id": "RUFF-F822",
	"name": "undefined export",
	"description": "Undefined name `<value>` in `__all__`",
	"help_uri": "https://docs.astral.sh/ruff/rules/undefined-export/",
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
	"ruff_code": "F822",
	"ruff_linter": "Pyflakes",
	"ruff_name": "undefined-export",
	"ruff_since": "v0.0.25",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
