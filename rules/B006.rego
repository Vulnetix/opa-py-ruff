# SPDX-License-Identifier: Apache-2.0
# Ruff rule B006 (flake8-bugbear): mutable argument default
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b006

import rego.v1

metadata := {
	"id": "RUFF-B006",
	"name": "mutable argument default",
	"description": "Do not use mutable data structures for argument defaults",
	"help_uri": "https://docs.astral.sh/ruff/rules/mutable-argument-default/",
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
	"ruff_code": "B006",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "mutable-argument-default",
	"ruff_since": "v0.0.92",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|\(\))`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not use mutable data structures for argument defaults",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
