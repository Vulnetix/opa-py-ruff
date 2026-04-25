# SPDX-License-Identifier: Apache-2.0
# Ruff rule S603 (flake8-bandit): subprocess without shell equals true
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s603

import rego.v1

metadata := {
	"id": "RUFF-S603",
	"name": "subprocess without shell equals true",
	"description": "`subprocess` call: check for execution of untrusted input",
	"help_uri": "https://docs.astral.sh/ruff/rules/subprocess-without-shell-equals-true/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S603",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "subprocess-without-shell-equals-true",
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
	regex.match(`\bsubprocess\.(call|run|Popen|check_output)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "subprocess call - review for user controlled input",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
