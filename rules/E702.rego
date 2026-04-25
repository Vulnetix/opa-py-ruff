# SPDX-License-Identifier: Apache-2.0
# Ruff rule E702 (pycodestyle): multiple statements on one line semicolon
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e702

import rego.v1

metadata := {
	"id": "RUFF-E702",
	"name": "multiple statements on one line semicolon",
	"description": "Multiple statements on one line (semicolon)",
	"help_uri": "https://docs.astral.sh/ruff/rules/multiple-statements-on-one-line-semicolon/",
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
	"ruff_code": "E702",
	"ruff_linter": "pycodestyle",
	"ruff_name": "multiple-statements-on-one-line-semicolon",
	"ruff_since": "v0.0.245",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
