# SPDX-License-Identifier: Apache-2.0
# Ruff rule B008 (flake8-bugbear): function call in default argument
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b008

import rego.v1

metadata := {
	"id": "RUFF-B008",
	"name": "function call in default argument",
	"description": "Do not perform function call `<value>` in argument defaults; instead, perform the call within the function, or read the default from a module-level singleton variable",
	"help_uri": "https://docs.astral.sh/ruff/rules/function-call-in-default-argument/",
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
	"ruff_code": "B008",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "function-call-in-default-argument",
	"ruff_since": "v0.0.102",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\([^)]*=\s*\w+\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not perform function call in argument defaults",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
