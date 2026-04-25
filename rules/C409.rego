# SPDX-License-Identifier: Apache-2.0
# Ruff rule C409 (flake8-comprehensions): unnecessary literal within tuple call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c409

import rego.v1

metadata := {
	"id": "RUFF-C409",
	"name": "unnecessary literal within tuple call",
	"description": "Unnecessary list literal passed to `tuple()` (rewrite as a tuple literal)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-literal-within-tuple-call/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-comprehensions", "c"],
	"ruff_code": "C409",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-literal-within-tuple-call",
	"ruff_since": "v0.0.66",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
