# SPDX-License-Identifier: Apache-2.0
# Ruff rule S607 (flake8-bandit): start process with partial path
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s607

import rego.v1

metadata := {
	"id": "RUFF-S607",
	"name": "start process with partial path",
	"description": "Starting a process with a partial executable path",
	"help_uri": "https://docs.astral.sh/ruff/rules/start-process-with-partial-path/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S607",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "start-process-with-partial-path",
	"ruff_since": "v0.0.262",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`subprocess\.[A-Za-z]+\s*\(\s*["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Starting a process with a partial executable path",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
