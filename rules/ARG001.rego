# SPDX-License-Identifier: Apache-2.0
# Ruff rule ARG001 (flake8-unused-arguments): unused function argument
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_arg001

import rego.v1

metadata := {
	"id": "RUFF-ARG001",
	"name": "unused function argument",
	"description": "Unused function argument: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-function-argument/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-unused-arguments", "arg"],
	"ruff_code": "ARG001",
	"ruff_linter": "flake8-unused-arguments",
	"ruff_name": "unused-function-argument",
	"ruff_since": "v0.0.168",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\([^)]+\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unused function argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
