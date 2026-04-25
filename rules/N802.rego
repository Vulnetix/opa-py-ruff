# SPDX-License-Identifier: Apache-2.0
# Ruff rule N802 (pep8-naming): invalid function name
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n802

import rego.v1

metadata := {
	"id": "RUFF-N802",
	"name": "invalid function name",
	"description": "Function name `<value>` should be lowercase",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-function-name/",
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
	"ruff_code": "N802",
	"ruff_linter": "pep8-naming",
	"ruff_name": "invalid-function-name",
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
	regex.match(`^def\s+[A-Z]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Function name should be lowercase",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
