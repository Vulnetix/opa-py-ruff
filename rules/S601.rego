# SPDX-License-Identifier: Apache-2.0
# Ruff rule S601 (flake8-bandit): paramiko call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s601

import rego.v1

metadata := {
	"id": "RUFF-S601",
	"name": "paramiko call",
	"description": "Possible shell injection via Paramiko call; check inputs are properly sanitized",
	"help_uri": "https://docs.astral.sh/ruff/rules/paramiko-call/",
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
	"ruff_code": "S601",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "paramiko-call",
	"ruff_since": "v0.0.270",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.exec_command\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Paramiko: possible shell injection via exec_command",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
