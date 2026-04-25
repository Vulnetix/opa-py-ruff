# SPDX-License-Identifier: Apache-2.0
# Ruff rule S105 (flake8-bandit): hardcoded password string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s105

import rego.v1

metadata := {
	"id": "RUFF-S105",
	"name": "hardcoded password string",
	"description": "Possible hardcoded password assigned to: '{}'",
	"help_uri": "https://docs.astral.sh/ruff/rules/hardcoded-password-string/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [259],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S105",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "hardcoded-password-string",
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
	regex.match(`(?i)(password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']{3,}["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded password string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
