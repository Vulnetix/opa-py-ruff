# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT020 (flake8-pytest-style): pytest deprecated yield fixture
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt020

import rego.v1

metadata := {
	"id": "RUFF-PT020",
	"name": "pytest deprecated yield fixture",
	"description": "`@pytest.yield_fixture` is deprecated, use `@pytest.fixture`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-deprecated-yield-fixture/",
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
	"ruff_code": "PT020",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-deprecated-yield-fixture",
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
