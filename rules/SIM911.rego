# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM911 (flake8-simplify): zip dict keys and values
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim911

import rego.v1

metadata := {
	"id": "RUFF-SIM911",
	"name": "zip dict keys and values",
	"description": "Use `<value>` instead of `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/zip-dict-keys-and-values/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM911",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "zip-dict-keys-and-values",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
