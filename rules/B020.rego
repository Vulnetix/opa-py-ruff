# SPDX-License-Identifier: Apache-2.0
# Ruff rule B020 (flake8-bugbear): loop variable overrides iterator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b020

import rego.v1

metadata := {
	"id": "RUFF-B020",
	"name": "loop variable overrides iterator",
	"description": "Loop control variable `<value>` overrides iterable it iterates",
	"help_uri": "https://docs.astral.sh/ruff/rules/loop-variable-overrides-iterator/",
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
	"ruff_code": "B020",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "loop-variable-overrides-iterator",
	"ruff_since": "v0.0.121",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+\w+:\s*\n.*\w+\[\w+\]\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Loop control variable overrides iterable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
