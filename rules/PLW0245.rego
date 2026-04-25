# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0245 (Pylint): super without brackets
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0245

import rego.v1

metadata := {
	"id": "RUFF-PLW0245",
	"name": "super without brackets",
	"description": "`super` call is missing parentheses",
	"help_uri": "https://docs.astral.sh/ruff/rules/super-without-brackets/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0245",
	"ruff_linter": "Pylint",
	"ruff_name": "super-without-brackets",
	"ruff_since": "0.5.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`super\s*\(\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "super() call missing __class__ cell",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
