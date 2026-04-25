# SPDX-License-Identifier: Apache-2.0
# Ruff rule E101 (pycodestyle): mixed spaces and tabs
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e101

import rego.v1

metadata := {
	"id": "RUFF-E101",
	"name": "mixed spaces and tabs",
	"description": "Indentation contains mixed spaces and tabs",
	"help_uri": "https://docs.astral.sh/ruff/rules/mixed-spaces-and-tabs/",
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
	"ruff_code": "E101",
	"ruff_linter": "pycodestyle",
	"ruff_name": "mixed-spaces-and-tabs",
	"ruff_since": "v0.0.229",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\t`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Indentation contains mixed spaces and tabs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
