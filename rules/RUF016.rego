# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF016 (Ruff-specific rules): invalid index type
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf016

import rego.v1

metadata := {
	"id": "RUFF-RUF016",
	"name": "invalid index type",
	"description": "Slice in indexed access to type `<value>` uses type `<value>` instead of an integer",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-index-type/",
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
	"ruff_code": "RUF016",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "invalid-index-type",
	"ruff_since": "v0.0.278",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
