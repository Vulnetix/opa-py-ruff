# SPDX-License-Identifier: Apache-2.0
# Ruff rule DTZ001 (flake8-datetimez): call datetime without tzinfo
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dtz001

import rego.v1

metadata := {
	"id": "RUFF-DTZ001",
	"name": "call datetime without tzinfo",
	"description": "`datetime.datetime()` called without a `tzinfo` argument",
	"help_uri": "https://docs.astral.sh/ruff/rules/call-datetime-without-tzinfo/",
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
	"ruff_code": "DTZ001",
	"ruff_linter": "flake8-datetimez",
	"ruff_name": "call-datetime-without-tzinfo",
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
	regex.match(`datetime\.datetime\s*\((?!.*tzinfo)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "datetime() without tzinfo argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
