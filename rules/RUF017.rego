# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF017 (Ruff-specific rules): quadratic list summation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf017

import rego.v1

metadata := {
	"id": "RUFF-RUF017",
	"name": "quadratic list summation",
	"description": "Avoid quadratic list summation",
	"help_uri": "https://docs.astral.sh/ruff/rules/quadratic-list-summation/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF017",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "quadratic-list-summation",
	"ruff_since": "v0.0.285",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bQuadratic\b|\bO\(n\^2\)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid quadratic list summation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
