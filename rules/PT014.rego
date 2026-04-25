# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT014 (flake8-pytest-style): pytest duplicate parametrize test cases
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt014

import rego.v1

metadata := {
	"id": "RUFF-PT014",
	"name": "pytest duplicate parametrize test cases",
	"description": "Duplicate of test case at index <value> in `pytest.mark.parametrize`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-duplicate-parametrize-test-cases/",
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
	"ruff_code": "PT014",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-duplicate-parametrize-test-cases",
	"ruff_since": "v0.0.285",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
