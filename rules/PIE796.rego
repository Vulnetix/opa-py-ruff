# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE796 (flake8-pie): non unique enums
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie796

import rego.v1

metadata := {
	"id": "RUFF-PIE796",
	"name": "non unique enums",
	"description": "Enum contains duplicate value: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-unique-enums/",
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
	"ruff_code": "PIE796",
	"ruff_linter": "flake8-pie",
	"ruff_name": "non-unique-enums",
	"ruff_since": "v0.0.224",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`class\s+\w+.*Enum.*:\s*\n.*=\s*\d+\s*\n.*=\s*\d+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Enum without unique values",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
