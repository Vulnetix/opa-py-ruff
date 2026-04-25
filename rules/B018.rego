# SPDX-License-Identifier: Apache-2.0
# Ruff rule B018 (flake8-bugbear): useless expression
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b018

import rego.v1

metadata := {
	"id": "RUFF-B018",
	"name": "useless expression",
	"description": "Found useless expression. Either assign it to a variable or remove it.",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-expression/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B018",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "useless-expression",
	"ruff_since": "v0.0.100",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s+["\'](?!docstring)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Useless expression — statement has no effect",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
