# SPDX-License-Identifier: Apache-2.0
# Ruff rule G004 (flake8-logging-format): logging f string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_g004

import rego.v1

metadata := {
	"id": "RUFF-G004",
	"name": "logging f string",
	"description": "Logging statement uses f-string",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-f-string/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-logging-format", "g"],
	"ruff_code": "G004",
	"ruff_linter": "flake8-logging-format",
	"ruff_name": "logging-f-string",
	"ruff_since": "v0.0.236",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`logging\.(debug|info|warning|error|critical)\s*\(\s*f["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Logging uses f-string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
