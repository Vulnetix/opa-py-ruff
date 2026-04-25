# SPDX-License-Identifier: Apache-2.0
# Ruff rule N806 (pep8-naming): non lowercase variable in function
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n806

import rego.v1

metadata := {
	"id": "RUFF-N806",
	"name": "non lowercase variable in function",
	"description": "Variable `<value>` in function should be lowercase",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-lowercase-variable-in-function/",
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
	"ruff_code": "N806",
	"ruff_linter": "pep8-naming",
	"ruff_name": "non-lowercase-variable-in-function",
	"ruff_since": "v0.0.89",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s+[A-Z][A-Z_]+=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Variable in function should be lowercase",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
