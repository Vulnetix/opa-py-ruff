# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0206 (Pylint): property with parameters
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0206

import rego.v1

metadata := {
	"id": "RUFF-PLR0206",
	"name": "property with parameters",
	"description": "Cannot have defined parameters for properties",
	"help_uri": "https://docs.astral.sh/ruff/rules/property-with-parameters/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR0206",
	"ruff_linter": "Pylint",
	"ruff_name": "property-with-parameters",
	"ruff_since": "v0.0.153",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`@property\s*\n\s*def\s+\w+\s*\(\s*self\s*,`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Property with parameters",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
