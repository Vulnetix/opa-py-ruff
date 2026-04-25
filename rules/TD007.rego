# SPDX-License-Identifier: Apache-2.0
# Ruff rule TD007 (flake8-todos): missing space after todo colon
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_td007

import rego.v1

metadata := {
	"id": "RUFF-TD007",
	"name": "missing space after todo colon",
	"description": "Missing space after colon in TODO",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-space-after-todo-colon/",
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
	"ruff_code": "TD007",
	"ruff_linter": "flake8-todos",
	"ruff_name": "missing-space-after-todo-colon",
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
	regex.match(`#\s*TODO\b.+\n.+#\s*TODO\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Multiple TODOs in sequence",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
