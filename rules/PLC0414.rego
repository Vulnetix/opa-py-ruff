# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0414 (Pylint): useless import alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0414

import rego.v1

metadata := {
	"id": "RUFF-PLC0414",
	"name": "useless import alias",
	"description": "Import alias does not rename original package",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-import-alias/",
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
	"ruff_code": "PLC0414",
	"ruff_linter": "Pylint",
	"ruff_name": "useless-import-alias",
	"ruff_since": "v0.0.156",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^import\s+\S+\s+as\s+\S+$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Import alias does not rename original package",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
