# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT021 (flake8-pytest-style): pytest fixture finalizer callback
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt021

import rego.v1

metadata := {
	"id": "RUFF-PT021",
	"name": "pytest fixture finalizer callback",
	"description": "Use `yield` instead of `request.addfinalizer`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-fixture-finalizer-callback/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pytest-style", "pt"],
	"ruff_code": "PT021",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-fixture-finalizer-callback",
	"ruff_since": "v0.0.208",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
