# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW2101 (Pylint): useless with lock
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw2101

import rego.v1

metadata := {
	"id": "RUFF-PLW2101",
	"name": "useless with lock",
	"description": "Threading lock directly created in `with` statement has no effect",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-with-lock/",
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
	"ruff_code": "PLW2101",
	"ruff_linter": "Pylint",
	"ruff_name": "useless-with-lock",
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
	regex.match(`with\s+lock\s*:\s*\n\s*(pass|\.\.\.)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Useless with lock statement",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
