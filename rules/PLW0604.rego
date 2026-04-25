# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0604 (Pylint): global at module level
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0604

import rego.v1

metadata := {
	"id": "RUFF-PLW0604",
	"name": "global at module level",
	"description": "`global` at module level is redundant",
	"help_uri": "https://docs.astral.sh/ruff/rules/global-at-module-level/",
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
	"ruff_code": "PLW0604",
	"ruff_linter": "Pylint",
	"ruff_name": "global-at-module-level",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^global\s+\w+$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Using global for a variable only assigned at module level",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
