# SPDX-License-Identifier: Apache-2.0
# Ruff rule TD006 (flake8-todos): invalid todo capitalization
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_td006

import rego.v1

metadata := {
	"id": "RUFF-TD006",
	"name": "invalid todo capitalization",
	"description": "Invalid TODO capitalization: `<value>` should be `TODO`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-todo-capitalization/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-todos", "td"],
	"ruff_code": "TD006",
	"ruff_linter": "flake8-todos",
	"ruff_name": "invalid-todo-capitalization",
	"ruff_since": "v0.0.269",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#\s*todo\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "TODO in lowercase",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
