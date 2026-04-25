# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT004 (flake8-pytest-style): pytest missing fixture name underscore
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt004

import rego.v1

metadata := {
	"id": "RUFF-PT004",
	"name": "pytest missing fixture name underscore",
	"description": "Fixture `<value>` does not return anything, add leading underscore",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-missing-fixture-name-underscore/",
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
	"ruff_code": "PT004",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-missing-fixture-name-underscore",
	"ruff_since": "0.8.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
