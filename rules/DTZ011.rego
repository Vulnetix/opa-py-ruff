# SPDX-License-Identifier: Apache-2.0
# Ruff rule DTZ011 (flake8-datetimez): call date today
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dtz011

import rego.v1

metadata := {
	"id": "RUFF-DTZ011",
	"name": "call date today",
	"description": "`datetime.date.today()` used",
	"help_uri": "https://docs.astral.sh/ruff/rules/call-date-today/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-datetimez", "dtz"],
	"ruff_code": "DTZ011",
	"ruff_linter": "flake8-datetimez",
	"ruff_name": "call-date-today",
	"ruff_since": "v0.0.188",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`datetime\.date\.today\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "datetime.date.today() returns local date without timezone",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
