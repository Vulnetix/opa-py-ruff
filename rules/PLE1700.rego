# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1700 (Pylint): yield from in async function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1700

import rego.v1

metadata := {
	"id": "RUFF-PLE1700",
	"name": "yield from in async function",
	"description": "`yield from` statement in async function; use `async for` instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/yield-from-in-async-function/",
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
	"ruff_code": "PLE1700",
	"ruff_linter": "Pylint",
	"ruff_name": "yield-from-in-async-function",
	"ruff_since": "v0.0.271",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
