# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1206 (Pylint): logging too few args
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1206

import rego.v1

metadata := {
	"id": "RUFF-PLE1206",
	"name": "logging too few args",
	"description": "Not enough arguments for `logging` format string",
	"help_uri": "https://docs.astral.sh/ruff/rules/logging-too-few-args/",
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
	"ruff_code": "PLE1206",
	"ruff_linter": "Pylint",
	"ruff_name": "logging-too-few-args",
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
	regex.match(`logging\.\w+\s*\(.*\{.*\}.*\.format`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Logging format with wrong args",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
