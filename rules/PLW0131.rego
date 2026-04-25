# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW0131 (Pylint): named expr without context
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw0131

import rego.v1

metadata := {
	"id": "RUFF-PLW0131",
	"name": "named expr without context",
	"description": "Named expression used without context",
	"help_uri": "https://docs.astral.sh/ruff/rules/named-expr-without-context/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW0131",
	"ruff_linter": "Pylint",
	"ruff_name": "named-expr-without-context",
	"ruff_since": "v0.0.270",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\*\w+\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Named expression used without assignment",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
