# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE800 (flake8-pie): unnecessary spread
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie800

import rego.v1

metadata := {
	"id": "RUFF-PIE800",
	"name": "unnecessary spread",
	"description": "Unnecessary spread `**`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-spread/",
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
	"ruff_code": "PIE800",
	"ruff_linter": "flake8-pie",
	"ruff_name": "unnecessary-spread",
	"ruff_since": "v0.0.231",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\{[^}]*\*\*\w+\s*\}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary spread **dict into dict literal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
