# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF027 (Ruff-specific rules): missing f string syntax
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf027

import rego.v1

metadata := {
	"id": "RUFF-RUF027",
	"name": "missing f string syntax",
	"description": "Possible f-string without an `f` prefix",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-f-string-syntax/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF027",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "missing-f-string-syntax",
	"ruff_since": "v0.2.1",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
