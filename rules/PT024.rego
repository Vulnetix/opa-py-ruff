# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT024 (flake8-pytest-style): pytest unnecessary asyncio mark on fixture
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt024

import rego.v1

metadata := {
	"id": "RUFF-PT024",
	"name": "pytest unnecessary asyncio mark on fixture",
	"description": "`pytest.mark.asyncio` is unnecessary for fixtures",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-unnecessary-asyncio-mark-on-fixture/",
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
	"ruff_code": "PT024",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-unnecessary-asyncio-mark-on-fixture",
	"ruff_since": "v0.0.208",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
