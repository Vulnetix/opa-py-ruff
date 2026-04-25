# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC220 (flake8-async): create subprocess in async function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async220

import rego.v1

metadata := {
	"id": "RUFF-ASYNC220",
	"name": "create subprocess in async function",
	"description": "Async functions should not create subprocesses with blocking methods",
	"help_uri": "https://docs.astral.sh/ruff/rules/create-subprocess-in-async-function/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-async", "async"],
	"ruff_code": "ASYNC220",
	"ruff_linter": "flake8-async",
	"ruff_name": "create-subprocess-in-async-function",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
