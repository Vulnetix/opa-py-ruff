# SPDX-License-Identifier: Apache-2.0
# Ruff rule S404 (flake8-bandit): suspicious subprocess import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s404

import rego.v1

metadata := {
	"id": "RUFF-S404",
	"name": "suspicious subprocess import",
	"description": "`subprocess` module is possibly insecure",
	"help_uri": "https://docs.astral.sh/ruff/rules/suspicious-subprocess-import/",
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
	"ruff_code": "S404",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "suspicious-subprocess-import",
	"ruff_since": "v0.1.12",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^import\s+subprocess\b|^from\s+subprocess\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Consider possible security implications of subprocess module",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
