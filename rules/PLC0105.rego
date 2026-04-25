# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0105 (Pylint): type name incorrect variance
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0105

import rego.v1

metadata := {
	"id": "RUFF-PLC0105",
	"name": "type name incorrect variance",
	"description": "`<value>` name '<value>' does not reflect its <value>; consider renaming it to '<value>'",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-name-incorrect-variance/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plc"],
	"ruff_code": "PLC0105",
	"ruff_linter": "Pylint",
	"ruff_name": "type-name-incorrect-variance",
	"ruff_since": "v0.0.278",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`TypeVar\s*\(\s*["\'][^"\']*["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "TypeVar name does not match variable name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
