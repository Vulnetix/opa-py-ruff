# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC2401 (Pylint): non ascii name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc2401

import rego.v1

metadata := {
	"id": "RUFF-PLC2401",
	"name": "non ascii name",
	"description": "<value> name `<value>` contains a non-ASCII character",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-ascii-name/",
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
	"ruff_code": "PLC2401",
	"ruff_linter": "Pylint",
	"ruff_name": "non-ascii-name",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[àáâãäåæçèéêëìíîïðñòóôõöùúûüý]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Non-ASCII name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
