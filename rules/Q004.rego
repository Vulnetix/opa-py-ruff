# SPDX-License-Identifier: Apache-2.0
# Ruff rule Q004 (flake8-quotes): unnecessary escaped quote
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_q004

import rego.v1

metadata := {
	"id": "RUFF-Q004",
	"name": "unnecessary escaped quote",
	"description": "Unnecessary escape on inner quote character",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-escaped-quote/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-quotes", "q"],
	"ruff_code": "Q004",
	"ruff_linter": "flake8-quotes",
	"ruff_name": "unnecessary-escaped-quote",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#.*'`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary escape",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
