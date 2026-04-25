# SPDX-License-Identifier: Apache-2.0
# Ruff rule W605 (pycodestyle): invalid escape sequence
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_w605

import rego.v1

metadata := {
	"id": "RUFF-W605",
	"name": "invalid escape sequence",
	"description": "Invalid escape sequence: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-escape-sequence/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "w"],
	"ruff_code": "W605",
	"ruff_linter": "pycodestyle",
	"ruff_name": "invalid-escape-sequence",
	"ruff_since": "v0.0.85",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\\[^\\\'\"abfnrtvx0-9uU\n\r\t]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Invalid escape sequence",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
