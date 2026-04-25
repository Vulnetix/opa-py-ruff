# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0118 (Pylint): load before global declaration
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0118

import rego.v1

metadata := {
	"id": "RUFF-PLE0118",
	"name": "load before global declaration",
	"description": "Name `<value>` is used prior to global declaration on <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/load-before-global-declaration/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE0118",
	"ruff_linter": "Pylint",
	"ruff_name": "load-before-global-declaration",
	"ruff_since": "v0.0.174",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^class\s+\w+.*:\s*$\n(.*\n)*?\s+\w+\s*=\s*\w+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Name referenced before global statement",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
