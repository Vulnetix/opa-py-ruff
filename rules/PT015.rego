# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT015 (flake8-pytest-style): pytest assert always false
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt015

import rego.v1

metadata := {
	"id": "RUFF-PT015",
	"name": "pytest assert always false",
	"description": "Assertion always fails, replace with `pytest.fail()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-assert-always-false/",
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
	"ruff_code": "PT015",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-assert-always-false",
	"ruff_since": "v0.0.208",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`assert\s+False\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Assertion is always false — use pytest.fail()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
