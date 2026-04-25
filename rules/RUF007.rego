# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF007 (Ruff-specific rules): zip instead of pairwise
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf007

import rego.v1

metadata := {
	"id": "RUFF-RUF007",
	"name": "zip instead of pairwise",
	"description": "Prefer `itertools.pairwise()` over `zip()` when iterating over successive pairs",
	"help_uri": "https://docs.astral.sh/ruff/rules/zip-instead-of-pairwise/",
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
	"ruff_code": "RUF007",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "zip-instead-of-pairwise",
	"ruff_since": "v0.0.257",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
