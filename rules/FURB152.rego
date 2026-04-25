# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB152 (refurb): math constant
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb152

import rego.v1

metadata := {
	"id": "RUFF-FURB152",
	"name": "math constant",
	"description": "Replace `<value>` with `math.<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/math-constant/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB152",
	"ruff_linter": "refurb",
	"ruff_name": "math-constant",
	"ruff_since": "v0.1.6",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`math\.pi\s*\*\s*2|2\s*\*\s*math\.pi`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use math.tau instead of math.pi * 2",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
