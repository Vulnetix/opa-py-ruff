# SPDX-License-Identifier: Apache-2.0
# Ruff rule E231 (pycodestyle): missing whitespace
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e231

import rego.v1

metadata := {
	"id": "RUFF-E231",
	"name": "missing whitespace",
	"description": "Missing whitespace after {}",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-whitespace/",
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
	"ruff_code": "E231",
	"ruff_linter": "pycodestyle",
	"ruff_name": "missing-whitespace",
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
