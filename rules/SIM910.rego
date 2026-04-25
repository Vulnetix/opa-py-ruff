# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM910 (flake8-simplify): dict get with none default
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim910

import rego.v1

metadata := {
	"id": "RUFF-SIM910",
	"name": "dict get with none default",
	"description": "Use `<value>` instead of `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/dict-get-with-none-default/",
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
	"ruff_code": "SIM910",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "dict-get-with-none-default",
	"ruff_since": "v0.0.261",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
