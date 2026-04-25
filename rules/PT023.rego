# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT023 (flake8-pytest-style): pytest incorrect mark parentheses style
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt023

import rego.v1

metadata := {
	"id": "RUFF-PT023",
	"name": "pytest incorrect mark parentheses style",
	"description": "Use `@pytest.mark.<value><value>` over `@pytest.mark.<value><value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-incorrect-mark-parentheses-style/",
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
	"ruff_code": "PT023",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-incorrect-mark-parentheses-style",
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
	regex.match(`@pytest\.mark\.\w+\(\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "@pytest.mark.xxx() with no arguments",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
