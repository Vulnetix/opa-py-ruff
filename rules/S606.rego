# SPDX-License-Identifier: Apache-2.0
# Ruff rule S606 (flake8-bandit): start process with no shell
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s606

import rego.v1

metadata := {
	"id": "RUFF-S606",
	"name": "start process with no shell",
	"description": "Starting a process without a shell",
	"help_uri": "https://docs.astral.sh/ruff/rules/start-process-with-no-shell/",
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
	"ruff_code": "S606",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "start-process-with-no-shell",
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
	regex.match(`\bos\.system\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Starting a process without a shell",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
