# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI064 (flake8-pyi): redundant final literal
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi064

import rego.v1

metadata := {
	"id": "RUFF-PYI064",
	"name": "redundant final literal",
	"description": "`Final[Literal[<value>]]` can be replaced with a bare `Final`",
	"help_uri": "https://docs.astral.sh/ruff/rules/redundant-final-literal/",
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
	"ruff_code": "PYI064",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "redundant-final-literal",
	"ruff_since": "0.8.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Final\[None\]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Final[None] should be just None",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
