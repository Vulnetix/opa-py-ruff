# SPDX-License-Identifier: Apache-2.0
# Ruff rule B033 (flake8-bugbear): duplicate value
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b033

import rego.v1

metadata := {
	"id": "RUFF-B033",
	"name": "duplicate value",
	"description": "Sets should not contain duplicate item `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-value/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B033",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "duplicate-value",
	"ruff_since": "v0.0.271",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\{[^}]*,\s*[^}]*\}\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate value in set literal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
