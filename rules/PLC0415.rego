# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC0415 (Pylint): import outside top level
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc0415

import rego.v1

metadata := {
	"id": "RUFF-PLC0415",
	"name": "import outside top level",
	"description": "`import` should be at the top-level of a file",
	"help_uri": "https://docs.astral.sh/ruff/rules/import-outside-top-level/",
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
	"ruff_code": "PLC0415",
	"ruff_linter": "Pylint",
	"ruff_name": "import-outside-top-level",
	"ruff_since": "0.12.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s+import\s+|^\s+from\s+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Import at non-toplevel",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
