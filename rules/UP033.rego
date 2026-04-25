# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP033 (pyupgrade): lru cache with maxsize none
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up033

import rego.v1

metadata := {
	"id": "RUFF-UP033",
	"name": "lru cache with maxsize none",
	"description": "Use `@functools.cache` instead of `@functools.lru_cache(maxsize=None)`",
	"help_uri": "https://docs.astral.sh/ruff/rules/lru-cache-with-maxsize-none/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP033",
	"ruff_linter": "pyupgrade",
	"ruff_name": "lru-cache-with-maxsize-none",
	"ruff_since": "v0.0.225",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
