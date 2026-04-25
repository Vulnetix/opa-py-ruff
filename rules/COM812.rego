# SPDX-License-Identifier: Apache-2.0
# Ruff rule COM812 (flake8-commas): missing trailing comma
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_com812

import rego.v1

metadata := {
	"id": "RUFF-COM812",
	"name": "missing trailing comma",
	"description": "Trailing comma missing",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-trailing-comma/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-commas", "com"],
	"ruff_code": "COM812",
	"ruff_linter": "flake8-commas",
	"ruff_name": "missing-trailing-comma",
	"ruff_since": "v0.0.223",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`,\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Trailing comma missing",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
