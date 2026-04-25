# SPDX-License-Identifier: Apache-2.0
# Ruff rule E222 (pycodestyle): multiple spaces after operator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e222

import rego.v1

metadata := {
	"id": "RUFF-E222",
	"name": "multiple spaces after operator",
	"description": "Multiple spaces after operator",
	"help_uri": "https://docs.astral.sh/ruff/rules/multiple-spaces-after-operator/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E222",
	"ruff_linter": "pycodestyle",
	"ruff_name": "multiple-spaces-after-operator",
	"ruff_since": "v0.0.269",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
