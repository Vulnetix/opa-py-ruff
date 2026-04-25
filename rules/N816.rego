# SPDX-License-Identifier: Apache-2.0
# Ruff rule N816 (pep8-naming): mixed case variable in global scope
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_n816

import rego.v1

metadata := {
	"id": "RUFF-N816",
	"name": "mixed case variable in global scope",
	"description": "Variable `<value>` in global scope should not be mixedCase",
	"help_uri": "https://docs.astral.sh/ruff/rules/mixed-case-variable-in-global-scope/",
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
	"ruff_code": "N816",
	"ruff_linter": "pep8-naming",
	"ruff_name": "mixed-case-variable-in-global-scope",
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
	regex.match(`^\s+[a-z][A-Z]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Mixedcase variable in global scope",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
