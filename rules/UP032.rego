# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP032 (pyupgrade): f string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up032

import rego.v1

metadata := {
	"id": "RUFF-UP032",
	"name": "f string",
	"description": "Use f-string instead of `format` call",
	"help_uri": "https://docs.astral.sh/ruff/rules/f-string/",
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
	"ruff_code": "UP032",
	"ruff_linter": "pyupgrade",
	"ruff_name": "f-string",
	"ruff_since": "v0.0.224",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.format\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use f-string instead of str.format()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
