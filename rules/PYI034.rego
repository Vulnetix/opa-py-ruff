# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI034 (flake8-pyi): non self return type
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi034

import rego.v1

metadata := {
	"id": "RUFF-PYI034",
	"name": "non self return type",
	"description": "`__new__` methods usually return `self` at runtime",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-self-return-type/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI034",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "non-self-return-type",
	"ruff_since": "v0.0.271",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`-> Self\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Return Self in classmethod",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
