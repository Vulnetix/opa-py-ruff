# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM110 (flake8-simplify): reimplemented builtin
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim110

import rego.v1

metadata := {
	"id": "RUFF-SIM110",
	"name": "reimplemented builtin",
	"description": "Use `<value>` instead of `for` loop",
	"help_uri": "https://docs.astral.sh/ruff/rules/reimplemented-builtin/",
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
	"ruff_code": "SIM110",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "reimplemented-builtin",
	"ruff_since": "v0.0.211",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+\w+:\s*\n\s+if\s+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use any()/all() instead of for loop with conditional",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
