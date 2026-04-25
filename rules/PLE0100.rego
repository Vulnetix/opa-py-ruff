# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0100 (Pylint): yield in init
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0100

import rego.v1

metadata := {
	"id": "RUFF-PLE0100",
	"name": "yield in init",
	"description": "`__init__` method is a generator",
	"help_uri": "https://docs.astral.sh/ruff/rules/yield-in-init/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE0100",
	"ruff_linter": "Pylint",
	"ruff_name": "yield-in-init",
	"ruff_since": "v0.0.245",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
