# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW2901 (Pylint): redefined loop name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw2901

import rego.v1

metadata := {
	"id": "RUFF-PLW2901",
	"name": "redefined loop name",
	"description": "Outer <value> variable `<value>` overwritten by inner <value> target",
	"help_uri": "https://docs.astral.sh/ruff/rules/redefined-loop-name/",
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
	"ruff_code": "PLW2901",
	"ruff_linter": "Pylint",
	"ruff_name": "redefined-loop-name",
	"ruff_since": "v0.0.252",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+(\w+)\s+in\s+.+:\s*\n.*\1\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Outer for loop variable overwritten by inner assignment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
