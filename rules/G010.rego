# SPDX-License-Identifier: Apache-2.0
# Ruff rule G010 (flake8-logging-format): logging warn
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_g010

import rego.v1

metadata := {
	"id": "RUFF-G010",
	"name": "logging warn",
	"description": "Logging statement uses `warn` instead of `warning`",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-warn/",
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
	"ruff_code": "G010",
	"ruff_linter": "flake8-logging-format",
	"ruff_name": "logging-warn",
	"ruff_since": "v0.0.236",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\blogging\.warn\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "logging.warn is deprecated, use logging.warning",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
