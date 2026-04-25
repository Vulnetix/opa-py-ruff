# SPDX-License-Identifier: Apache-2.0
# Ruff rule F841 (Pyflakes): unused variable
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_f841

import rego.v1

metadata := {
	"id": "RUFF-F841",
	"name": "unused variable",
	"description": "Local variable `<value>` is assigned to but never used",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-variable/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyflakes", "f"],
	"ruff_code": "F841",
	"ruff_linter": "Pyflakes",
	"ruff_name": "unused-variable",
	"ruff_since": "v0.0.22",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s+\w+\s*=\s*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Local variable assigned but never used",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
