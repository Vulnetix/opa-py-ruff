# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM114 (flake8-simplify): if with same arms
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim114

import rego.v1

metadata := {
	"id": "RUFF-SIM114",
	"name": "if with same arms",
	"description": "Combine `if` branches using logical `or` operator",
	"help_uri": "https://docs.astral.sh/ruff/rules/if-with-same-arms/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM114",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "if-with-same-arms",
	"ruff_since": "v0.0.246",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+\w+:\s*\n\s+.+\s*\n\s*elif\s+\w+:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Combine if branches using or",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
