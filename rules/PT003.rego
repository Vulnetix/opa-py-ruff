# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT003 (flake8-pytest-style): pytest extraneous scope function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt003

import rego.v1

metadata := {
	"id": "RUFF-PT003",
	"name": "pytest extraneous scope function",
	"description": "`scope='function'` is implied in `@pytest.fixture()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-extraneous-scope-function/",
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
	"ruff_code": "PT003",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-extraneous-scope-function",
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
	regex.match(`@pytest\.fixture\s*\(.*scope=["\']function["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "scope=function is the default",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
