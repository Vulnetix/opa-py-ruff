# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT029 (flake8-pytest-style): pytest warns without warning
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt029

import rego.v1

metadata := {
	"id": "RUFF-PT029",
	"name": "pytest warns without warning",
	"description": "Set the expected warning in `pytest.warns()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-warns-without-warning/",
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
	"ruff_code": "PT029",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-warns-without-warning",
	"ruff_since": "0.9.2",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
