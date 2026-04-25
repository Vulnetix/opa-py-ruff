# SPDX-License-Identifier: Apache-2.0
# Ruff rule RET504 (flake8-return): unnecessary assign
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ret504

import rego.v1

metadata := {
	"id": "RUFF-RET504",
	"name": "unnecessary assign",
	"description": "Unnecessary assignment to `<value>` before `return` statement",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-assign/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-return", "ret"],
	"ruff_code": "RET504",
	"ruff_linter": "flake8-return",
	"ruff_name": "unnecessary-assign",
	"ruff_since": "v0.0.154",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*=\s*[^\n]+\n\s*return\s+\1`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary assignment before return",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
