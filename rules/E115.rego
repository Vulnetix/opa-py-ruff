# SPDX-License-Identifier: Apache-2.0
# Ruff rule E115 (pycodestyle): no indented block comment
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e115

import rego.v1

metadata := {
	"id": "RUFF-E115",
	"name": "no indented block comment",
	"description": "Expected an indented block (comment)",
	"help_uri": "https://docs.astral.sh/ruff/rules/no-indented-block-comment/",
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
	"ruff_code": "E115",
	"ruff_linter": "pycodestyle",
	"ruff_name": "no-indented-block-comment",
	"ruff_since": "v0.0.269",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
