# SPDX-License-Identifier: Apache-2.0
# Ruff rule N803 (pep8-naming): invalid argument name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n803

import rego.v1

metadata := {
	"id": "RUFF-N803",
	"name": "invalid argument name",
	"description": "Argument name `<value>` should be lowercase",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-argument-name/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pep8-naming", "n"],
	"ruff_code": "N803",
	"ruff_linter": "pep8-naming",
	"ruff_name": "invalid-argument-name",
	"ruff_since": "v0.0.77",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\([^)]*[A-Z][a-z]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Argument name should be lowercase",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
