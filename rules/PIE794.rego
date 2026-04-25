# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE794 (flake8-pie): duplicate class field definition
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie794

import rego.v1

metadata := {
	"id": "RUFF-PIE794",
	"name": "duplicate class field definition",
	"description": "Class field `<value>` is defined multiple times",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-class-field-definition/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pie", "pie"],
	"ruff_code": "PIE794",
	"ruff_linter": "flake8-pie",
	"ruff_name": "duplicate-class-field-definition",
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
	regex.match(`class\s+\w+.*:\s*\n.*\w+\s*=\s*\w+\s*\n.*\1\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Class attribute defined multiple times",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
