# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE804 (flake8-pie): unnecessary dict kwargs
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie804

import rego.v1

metadata := {
	"id": "RUFF-PIE804",
	"name": "unnecessary dict kwargs",
	"description": "Unnecessary `dict` kwargs",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-dict-kwargs/",
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
	"ruff_code": "PIE804",
	"ruff_linter": "flake8-pie",
	"ruff_name": "unnecessary-dict-kwargs",
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
	regex.match(`def\s+\w+\s*\([^)]*\*\*kwargs\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "**kwargs in function definition",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
