# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE808 (flake8-pie): unnecessary range start
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie808

import rego.v1

metadata := {
	"id": "RUFF-PIE808",
	"name": "unnecessary range start",
	"description": "Unnecessary `start` argument in `range`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-range-start/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pie", "pie"],
	"ruff_code": "PIE808",
	"ruff_linter": "flake8-pie",
	"ruff_name": "unnecessary-range-start",
	"ruff_since": "v0.0.286",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`range\s*\(\s*0\s*,`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary start=0 in range",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
