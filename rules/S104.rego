# SPDX-License-Identifier: Apache-2.0
# Ruff rule S104 (flake8-bandit): hardcoded bind all interfaces
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s104

import rego.v1

metadata := {
	"id": "RUFF-S104",
	"name": "hardcoded bind all interfaces",
	"description": "Possible binding to all interfaces",
	"help_uri": "https://docs.astral.sh/ruff/rules/hardcoded-bind-all-interfaces/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S104",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "hardcoded-bind-all-interfaces",
	"ruff_since": "v0.0.116",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`0\.0\.0\.0|bind.*0\.0\.0\.0`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Binding to all interfaces",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
