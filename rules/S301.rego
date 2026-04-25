# SPDX-License-Identifier: Apache-2.0
# Ruff rule S301 (flake8-bandit): suspicious pickle usage
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s301

import rego.v1

metadata := {
	"id": "RUFF-S301",
	"name": "suspicious pickle usage",
	"description": "`pickle` and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-pickle-usage/",
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
	"ruff_code": "S301",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-pickle-usage",
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
	regex.match(`\bpickle\.(loads?|dumps?|Unpickler)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Pickle deserialisation can execute arbitrary code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
