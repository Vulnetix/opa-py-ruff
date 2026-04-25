# SPDX-License-Identifier: Apache-2.0
# Ruff rule ARG005 (flake8-unused-arguments): unused lambda argument
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_arg005

import rego.v1

metadata := {
	"id": "RUFF-ARG005",
	"name": "unused lambda argument",
	"description": "Unused lambda argument: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-lambda-argument/",
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
	"ruff_code": "ARG005",
	"ruff_linter": "flake8-unused-arguments",
	"ruff_name": "unused-lambda-argument",
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
	regex.match(`def\s+__\w+__\s*\([^)]+\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unused lambda argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
