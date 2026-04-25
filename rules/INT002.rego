# SPDX-License-Identifier: Apache-2.0
# Ruff rule INT002 (flake8-gettext): format in get text func call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_int002

import rego.v1

metadata := {
	"id": "RUFF-INT002",
	"name": "format in get text func call",
	"description": "`format` method in plural argument is resolved before function call",
	"help_uri": "https://docs.astral.sh/ruff/rules/format-in-get-text-func-call/",
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
	"ruff_code": "INT002",
	"ruff_linter": "flake8-gettext",
	"ruff_name": "format-in-get-text-func-call",
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
	regex.match(`_\s*\(\s*["\'].*\\\n`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Implicit string concatenation in gettext call",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
