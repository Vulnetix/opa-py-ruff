# SPDX-License-Identifier: Apache-2.0
# Ruff rule S604 (flake8-bandit): call with shell equals true
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s604

import rego.v1

metadata := {
	"id": "RUFF-S604",
	"name": "call with shell equals true",
	"description": "Function call with `shell=True` parameter identified, security issue",
	"help_uri": "https://docs.astral.sh/ruff/rules/call-with-shell-equals-true/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s"],
	"ruff_code": "S604",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "call-with-shell-equals-true",
	"ruff_since": "v0.0.262",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`os\.system\s*\(|commands\.getoutput\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Function call with shell=True",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
