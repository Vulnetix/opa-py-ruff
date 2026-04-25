# SPDX-License-Identifier: Apache-2.0
# Ruff rule S102 (flake8-bandit): exec builtin
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s102

import rego.v1

metadata := {
	"id": "RUFF-S102",
	"name": "exec builtin",
	"description": "Use of `exec` detected",
	"help_uri": "https://docs.astral.sh/ruff/rules/exec-builtin/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S102",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "exec-builtin",
	"ruff_since": "v0.0.116",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bexec\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of `exec` builtin",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
