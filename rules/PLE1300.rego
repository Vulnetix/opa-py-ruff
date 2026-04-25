# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1300 (Pylint): bad string format character
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1300

import rego.v1

metadata := {
	"id": "RUFF-PLE1300",
	"name": "bad string format character",
	"description": "Unsupported format character '<value>'",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-string-format-character/",
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
	"ruff_code": "PLE1300",
	"ruff_linter": "Pylint",
	"ruff_name": "bad-string-format-character",
	"ruff_since": "v0.0.283",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`["\'].*%[^sdiouxXeEfFgGcrsa%]["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Bad string format type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
