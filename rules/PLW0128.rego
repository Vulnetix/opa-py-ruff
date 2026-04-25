# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0128 (Pylint): redeclared assigned name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0128

import rego.v1

metadata := {
	"id": "RUFF-PLW0128",
	"name": "redeclared assigned name",
	"description": "Redeclared variable `<value>` in assignment",
	"help_uri": "https://docs.astral.sh/ruff/rules/redeclared-assigned-name/",
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
	"ruff_code": "PLW0128",
	"ruff_linter": "Pylint",
	"ruff_name": "redeclared-assigned-name",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*=\s*\w+\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Augmented assignment in chained comparison",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
