# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT018 (flake8-pytest-style): pytest composite assertion
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt018

import rego.v1

metadata := {
	"id": "RUFF-PT018",
	"name": "pytest composite assertion",
	"description": "Assertion should be broken down into multiple parts",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-composite-assertion/",
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
	"ruff_code": "PT018",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-composite-assertion",
	"ruff_since": "v0.0.208",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`assert\s+\w+\s+and\s+\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Assertion is composite — split into separate assertions",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
