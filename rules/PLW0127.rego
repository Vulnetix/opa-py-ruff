# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0127 (Pylint): self assigning variable
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0127

import rego.v1

metadata := {
	"id": "RUFF-PLW0127",
	"name": "self assigning variable",
	"description": "Self-assignment of variable `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/self-assigning-variable/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0127",
	"ruff_linter": "Pylint",
	"ruff_name": "self-assigning-variable",
	"ruff_since": "v0.0.281",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*,\s*\w+\s*=\s*\w+\s*,\s*\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Self-assignment of variables",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
