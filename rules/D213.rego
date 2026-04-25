# SPDX-License-Identifier: Apache-2.0
# Ruff rule D213 (pydocstyle): multi line summary second line
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d213

import rego.v1

metadata := {
	"id": "RUFF-D213",
	"name": "multi line summary second line",
	"description": "Multi-line docstring summary should start at the second line",
	"help_uri": "https://docs.astral.sh/ruff/rules/multi-line-summary-second-line/",
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
	"ruff_code": "D213",
	"ruff_linter": "pydocstyle",
	"ruff_name": "multi-line-summary-second-line",
	"ruff_since": "v0.0.69",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
