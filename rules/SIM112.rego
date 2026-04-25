# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM112 (flake8-simplify): uncapitalized environment variables
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim112

import rego.v1

metadata := {
	"id": "RUFF-SIM112",
	"name": "uncapitalized environment variables",
	"description": "Use capitalized environment variable `<value>` instead of `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/uncapitalized-environment-variables/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM112",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "uncapitalized-environment-variables",
	"ruff_since": "v0.0.218",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.environ\.get\s*\(\s*["\'][A-Z_]+["\']\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use UPPERCASE for env variables",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
