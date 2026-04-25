# SPDX-License-Identifier: Apache-2.0
# Ruff rule FBT003 (flake8-boolean-trap): boolean positional value in call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fbt003

import rego.v1

metadata := {
	"id": "RUFF-FBT003",
	"name": "boolean positional value in call",
	"description": "Boolean positional value in function call",
	"help_uri": "https://docs.astral.sh/ruff/rules/boolean-positional-value-in-call/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-boolean-trap", "fbt"],
	"ruff_code": "FBT003",
	"ruff_linter": "flake8-boolean-trap",
	"ruff_name": "boolean-positional-value-in-call",
	"ruff_since": "v0.0.127",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*\(\s*(True|False)\s*[,)]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Boolean positional value in function call",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
