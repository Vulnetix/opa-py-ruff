# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP045 (pyupgrade): non pep604 annotation optional
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up045

import rego.v1

metadata := {
	"id": "RUFF-UP045",
	"name": "non pep604 annotation optional",
	"description": "Use `X | None` for type annotations",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep604-annotation-optional/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP045",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep604-annotation-optional",
	"ruff_since": "0.12.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
