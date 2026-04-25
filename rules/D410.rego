# SPDX-License-Identifier: Apache-2.0
# Ruff rule D410 (pydocstyle): no blank line after section
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_d410

import rego.v1

metadata := {
	"id": "RUFF-D410",
	"name": "no blank line after section",
	"description": "Missing blank line after section ('<value>')",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-blank-line-after-section/",
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
	"ruff_code": "D410",
	"ruff_linter": "pydocstyle",
	"ruff_name": "no-blank-line-after-section",
	"ruff_since": "v0.0.71",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
