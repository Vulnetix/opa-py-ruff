# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF069 (Ruff-specific rules): float equality comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf069

import rego.v1

metadata := {
	"id": "RUFF-RUF069",
	"name": "float equality comparison",
	"description": "Unreliable floating point equality comparison `<value> <value> <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/float-equality-comparison/",
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
	"ruff_code": "RUF069",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "float-equality-comparison",
	"ruff_since": "0.15.1",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
