# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0602 (Pylint): global variable not assigned
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0602

import rego.v1

metadata := {
	"id": "RUFF-PLW0602",
	"name": "global variable not assigned",
	"description": "Using global for `<value>` but no assignment is done",
	"help_uri": "https://docs.astral.sh/ruff/rules/global-variable-not-assigned/",
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
	"ruff_code": "PLW0602",
	"ruff_linter": "Pylint",
	"ruff_name": "global-variable-not-assigned",
	"ruff_since": "v0.0.174",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^global\s+\w+\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Using global for a variable that has no assignment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
