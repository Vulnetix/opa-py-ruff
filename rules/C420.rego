# SPDX-License-Identifier: Apache-2.0
# Ruff rule C420 (flake8-comprehensions): unnecessary dict comprehension for iterable
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_c420

import rego.v1

metadata := {
	"id": "RUFF-C420",
	"name": "unnecessary dict comprehension for iterable",
	"description": "Unnecessary dict comprehension for iterable; use `dict.fromkeys` instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-dict-comprehension-for-iterable/",
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
	"ruff_code": "C420",
	"ruff_linter": "flake8-comprehensions",
	"ruff_name": "unnecessary-dict-comprehension-for-iterable",
	"ruff_since": "0.10.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
