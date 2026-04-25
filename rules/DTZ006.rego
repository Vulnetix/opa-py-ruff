# SPDX-License-Identifier: Apache-2.0
# Ruff rule DTZ006 (flake8-datetimez): call datetime fromtimestamp
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_dtz006

import rego.v1

metadata := {
	"id": "RUFF-DTZ006",
	"name": "call datetime fromtimestamp",
	"description": "`datetime.datetime.fromtimestamp()` called without a `tz` argument",
	"help_uri": "https://docs.astral.sh/ruff/rules/call-datetime-fromtimestamp/",
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
	"ruff_code": "DTZ006",
	"ruff_linter": "flake8-datetimez",
	"ruff_name": "call-datetime-fromtimestamp",
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
	regex.match(`datetime\.datetime\.fromtimestamp\s*\([^,)]+\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "datetime.fromtimestamp() without tz argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
