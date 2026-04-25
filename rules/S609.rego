# SPDX-License-Identifier: Apache-2.0
# Ruff rule S609 (flake8-bandit): unix command wildcard injection
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s609

import rego.v1

metadata := {
	"id": "RUFF-S609",
	"name": "unix command wildcard injection",
	"description": "Possible wildcard injection in call due to `*` usage",
	"help_uri": "https://docs.astral.sh/ruff/rules/unix-command-wildcard-injection/",
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
	"ruff_code": "S609",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "unix-command-wildcard-injection",
	"ruff_since": "v0.0.271",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`subprocess.*shell.*\*|glob\.\*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Possible wildcard injection in shell command",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
