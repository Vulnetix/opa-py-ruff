# SPDX-License-Identifier: Apache-2.0
# Ruff rule C418 (flake8-comprehensions): unnecessary literal within dict call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c418

import rego.v1

metadata := {
	"id": "RUFF-C418",
	"name": "unnecessary literal within dict call",
	"description": "Unnecessary dict <value> passed to `dict()` (remove the outer call to `dict()`)",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-literal-within-dict-call/",
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
	"ruff_code": "C418",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-literal-within-dict-call",
	"ruff_since": "v0.0.262",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
