# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF022 (Ruff-specific rules): unsorted dunder all
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf022

import rego.v1

metadata := {
	"id": "RUFF-RUF022",
	"name": "unsorted dunder all",
	"description": "`__all__` is not sorted",
	"help_uri": "https://docs.astral.sh/ruff/rules/unsorted-dunder-all/",
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
	"ruff_code": "RUF022",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unsorted-dunder-all",
	"ruff_since": "0.8.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
