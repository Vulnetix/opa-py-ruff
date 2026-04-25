# SPDX-License-Identifier: Apache-2.0
# Ruff rule PERF403 (Perflint): manual dict comprehension
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_perf403

import rego.v1

metadata := {
	"id": "RUFF-PERF403",
	"name": "manual dict comprehension",
	"description": "Use a dictionary comprehension instead of <value> for-loop",
	"help_uri": "https://docs.astral.sh/ruff/rules/manual-dict-comprehension/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "perflint", "perf"],
	"ruff_code": "PERF403",
	"ruff_linter": "Perflint",
	"ruff_name": "manual-dict-comprehension",
	"ruff_since": "0.5.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
