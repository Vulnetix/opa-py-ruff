# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE807 (flake8-pie): reimplemented container builtin
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie807

import rego.v1

metadata := {
	"id": "RUFF-PIE807",
	"name": "reimplemented container builtin",
	"description": "Prefer `<value>` over useless lambda",
	"help_uri": "https://docs.astral.sh/ruff/rules/reimplemented-container-builtin/",
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
	"ruff_code": "PIE807",
	"ruff_linter": "flake8-pie",
	"ruff_name": "reimplemented-container-builtin",
	"ruff_since": "v0.0.208",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`lambda\s*:\s*\[\]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "lambda: [] is equivalent to list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
