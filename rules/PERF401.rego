# SPDX-License-Identifier: Apache-2.0
# Ruff rule PERF401 (Perflint): manual list comprehension
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_perf401

import rego.v1

metadata := {
	"id": "RUFF-PERF401",
	"name": "manual list comprehension",
	"description": "Use <value> to create a transformed list",
	"help_uri": "https://docs.astral.sh/ruff/rules/manual-list-comprehension/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "perflint", "perf"],
	"ruff_code": "PERF401",
	"ruff_linter": "Perflint",
	"ruff_name": "manual-list-comprehension",
	"ruff_since": "v0.0.276",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+\w+:\s*\n\s+\w+\.append\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use list comprehension to create a transformed list",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
