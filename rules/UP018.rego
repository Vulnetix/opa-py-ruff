# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP018 (pyupgrade): native literals
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up018

import rego.v1

metadata := {
	"id": "RUFF-UP018",
	"name": "native literals",
	"description": "Unnecessary `<value>` call (rewrite as a literal)",
	"help_uri": "https://docs.astral.sh/ruff/rules/native-literals/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP018",
	"ruff_linter": "pyupgrade",
	"ruff_name": "native-literals",
	"ruff_since": "v0.0.193",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b(str|bytes|int|float)\s*\(\d+\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary call to str/bytes/int/float",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
