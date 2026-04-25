# SPDX-License-Identifier: Apache-2.0
# Ruff rule S302 (flake8-bandit): suspicious marshal usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s302

import rego.v1

metadata := {
	"id": "RUFF-S302",
	"name": "suspicious marshal usage",
	"description": "Deserialization with the `marshal` module is possibly dangerous",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-marshal-usage/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S302",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-marshal-usage",
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
	regex.match(`\bmarshal\.(loads?|dumps?)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Marshal deserialisation is not secure",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
