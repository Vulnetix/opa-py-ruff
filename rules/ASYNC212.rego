# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC212 (flake8-async): blocking http call httpx in async function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async212

import rego.v1

metadata := {
	"id": "RUFF-ASYNC212",
	"name": "blocking http call httpx in async function",
	"description": "Blocking httpx method <value>.<value>() in async context, use httpx.AsyncClient",
	"help_uri": "https://docs.astral.sh/ruff/rules/blocking-http-call-httpx-in-async-function/",
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
	"ruff_code": "ASYNC212",
	"ruff_linter": "flake8-async",
	"ruff_name": "blocking-http-call-httpx-in-async-function",
	"ruff_since": "0.15.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
