# SPDX-License-Identifier: Apache-2.0
# Ruff rule INT003 (flake8-gettext): printf in get text func call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_int003

import rego.v1

metadata := {
	"id": "RUFF-INT003",
	"name": "printf in get text func call",
	"description": "printf-style format in plural argument is resolved before function call",
	"help_uri": "https://docs.astral.sh/ruff/rules/printf-in-get-text-func-call/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-gettext", "int"],
	"ruff_code": "INT003",
	"ruff_linter": "flake8-gettext",
	"ruff_name": "printf-in-get-text-func-call",
	"ruff_since": "v0.0.260",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`_\s*\(\s*\w+\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Variable in gettext call",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
