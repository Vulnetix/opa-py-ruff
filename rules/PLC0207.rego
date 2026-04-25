# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0207 (Pylint): missing maxsplit arg
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0207

import rego.v1

metadata := {
	"id": "RUFF-PLC0207",
	"name": "missing maxsplit arg",
	"description": "String is split more times than necessary",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-maxsplit-arg/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plc"],
	"ruff_code": "PLC0207",
	"ruff_linter": "Pylint",
	"ruff_name": "missing-maxsplit-arg",
	"ruff_since": "0.15.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
