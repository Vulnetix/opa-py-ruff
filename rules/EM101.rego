# SPDX-License-Identifier: Apache-2.0
# Ruff rule EM101 (flake8-errmsg): raw string in exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_em101

import rego.v1

metadata := {
	"id": "RUFF-EM101",
	"name": "raw string in exception",
	"description": "Exception must not use a string literal, assign to variable first",
	"help_uri": "https://docs.astral.sh/ruff/rules/raw-string-in-exception/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-errmsg", "em"],
	"ruff_code": "EM101",
	"ruff_linter": "flake8-errmsg",
	"ruff_name": "raw-string-in-exception",
	"ruff_since": "v0.0.183",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`raise\s+\w+\s*\(\s*[f"\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "String literal as exception argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
