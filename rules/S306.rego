# SPDX-License-Identifier: Apache-2.0
# Ruff rule S306 (flake8-bandit): suspicious mktemp usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s306

import rego.v1

metadata := {
	"id": "RUFF-S306",
	"name": "suspicious mktemp usage",
	"description": "Use of insecure and deprecated function (`mktemp`)",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-mktemp-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S306",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-mktemp-usage",
	"ruff_since": "v0.0.258",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\btempfile\.mktemp\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of insecure and deprecated mktemp",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
