# SPDX-License-Identifier: Apache-2.0
# Ruff rule S113 (flake8-bandit): request without timeout
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s113

import rego.v1

metadata := {
	"id": "RUFF-S113",
	"name": "request without timeout",
	"description": "Probable use of `<value>` call without timeout",
	"help_uri": "https://docs.astral.sh/ruff/rules/request-without-timeout/",
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
	"ruff_code": "S113",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "request-without-timeout",
	"ruff_since": "v0.0.213",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`requests\.(get|post|put|patch|delete|head)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Request without timeout",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
