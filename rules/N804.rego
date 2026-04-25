# SPDX-License-Identifier: Apache-2.0
# Ruff rule N804 (pep8-naming): invalid first argument name for class method
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n804

import rego.v1

metadata := {
	"id": "RUFF-N804",
	"name": "invalid first argument name for class method",
	"description": "First argument of a class method should be named `cls`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-first-argument-name-for-class-method/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pep8-naming", "n"],
	"ruff_code": "N804",
	"ruff_linter": "pep8-naming",
	"ruff_name": "invalid-first-argument-name-for-class-method",
	"ruff_since": "v0.0.77",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`@classmethod\s*\n\s*def\s+\w+\s*\(\s*[^c]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "First argument of classmethod should be cls",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
