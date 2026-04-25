# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT001 (flake8-pytest-style): pytest fixture incorrect parentheses style
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt001

import rego.v1

metadata := {
	"id": "RUFF-PT001",
	"name": "pytest fixture incorrect parentheses style",
	"description": "Use `@pytest.fixture<value>` over `@pytest.fixture<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-fixture-incorrect-parentheses-style/",
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
	"ruff_code": "PT001",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-fixture-incorrect-parentheses-style",
	"ruff_since": "v0.0.208",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`@pytest\.fixture\s*\(\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "@pytest.fixture() without parentheses",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
