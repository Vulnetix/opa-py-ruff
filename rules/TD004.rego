# SPDX-License-Identifier: Apache-2.0
# Ruff rule TD004 (flake8-todos): missing todo colon
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_td004

import rego.v1

metadata := {
	"id": "RUFF-TD004",
	"name": "missing todo colon",
	"description": "Missing colon in TODO",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-todo-colon/",
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
	"ruff_code": "TD004",
	"ruff_linter": "flake8-todos",
	"ruff_name": "missing-todo-colon",
	"ruff_since": "v0.0.269",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#\s*TODO\b.*!`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Missing colon in TODO",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
