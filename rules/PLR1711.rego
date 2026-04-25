# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR1711 (Pylint): useless return
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr1711

import rego.v1

metadata := {
	"id": "RUFF-PLR1711",
	"name": "useless return",
	"description": "Useless `return` statement at end of function",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-return/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR1711",
	"ruff_linter": "Pylint",
	"ruff_name": "useless-return",
	"ruff_since": "v0.0.257",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`return\s+None\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Useless return statement at end of function",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
