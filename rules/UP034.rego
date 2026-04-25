# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP034 (pyupgrade): extraneous parentheses
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up034

import rego.v1

metadata := {
	"id": "RUFF-UP034",
	"name": "extraneous parentheses",
	"description": "Avoid extraneous parentheses",
	"help_uri": "https://docs.astral.sh/ruff/rules/extraneous-parentheses/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP034",
	"ruff_linter": "pyupgrade",
	"ruff_name": "extraneous-parentheses",
	"ruff_since": "v0.0.228",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`return\s*\(([^,)]+)\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Extraneous parentheses",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
