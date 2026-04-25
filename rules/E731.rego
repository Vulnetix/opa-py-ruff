# SPDX-License-Identifier: Apache-2.0
# Ruff rule E731 (pycodestyle): lambda assignment
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e731

import rego.v1

metadata := {
	"id": "RUFF-E731",
	"name": "lambda assignment",
	"description": "Do not assign a `lambda` expression, use a `def`",
	"help_uri": "https://docs.astral.sh/ruff/rules/lambda-assignment/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E731",
	"ruff_linter": "pycodestyle",
	"ruff_name": "lambda-assignment",
	"ruff_since": "v0.0.28",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b\w+\s*=\s*lambda\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not assign a lambda expression; use `def`",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
