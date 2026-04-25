# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM113 (flake8-simplify): enumerate for loop
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim113

import rego.v1

metadata := {
	"id": "RUFF-SIM113",
	"name": "enumerate for loop",
	"description": "Use `enumerate()` for index variable `<value>` in `for` loop",
	"help_uri": "https://docs.astral.sh/ruff/rules/enumerate-for-loop/",
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
	"ruff_code": "SIM113",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "enumerate-for-loop",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`enumerate\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use enumerate() for index/value pairs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
