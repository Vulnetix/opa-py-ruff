# SPDX-License-Identifier: Apache-2.0
# Ruff rule N801 (pep8-naming): invalid class name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n801

import rego.v1

metadata := {
	"id": "RUFF-N801",
	"name": "invalid class name",
	"description": "Class name `<value>` should use CapWords convention",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-class-name/",
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
	"ruff_code": "N801",
	"ruff_linter": "pep8-naming",
	"ruff_name": "invalid-class-name",
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
	regex.match(`^class\s+[a-z]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Class name should use CapWords convention",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
