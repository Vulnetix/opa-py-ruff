# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1205 (Pylint): logging too many args
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1205

import rego.v1

metadata := {
	"id": "RUFF-PLE1205",
	"name": "logging too many args",
	"description": "Too many arguments for `logging` format string",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-too-many-args/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE1205",
	"ruff_linter": "Pylint",
	"ruff_name": "logging-too-many-args",
	"ruff_since": "v0.0.252",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`logging\.\w+\s*\(.*%[sd].*,`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Logging format with wrong number of args",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
