# SPDX-License-Identifier: Apache-2.0
# Ruff rule D420 (pydocstyle): incorrect section order
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d420

import rego.v1

metadata := {
	"id": "RUFF-D420",
	"name": "incorrect section order",
	"description": "Section '<value>' appears after section '<value>' but should be before it",
	"help_uri": "https://docs.astral.sh/ruff/rules/incorrect-section-order/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pydocstyle", "d"],
	"ruff_code": "D420",
	"ruff_linter": "pydocstyle",
	"ruff_name": "incorrect-section-order",
	"ruff_since": "0.15.3",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
