# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP009 (pyupgrade): utf8 encoding declaration
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up009

import rego.v1

metadata := {
	"id": "RUFF-UP009",
	"name": "utf8 encoding declaration",
	"description": "UTF-8 encoding declaration is unnecessary",
	"help_uri": "https://docs.astral.sh/ruff/rules/utf8-encoding-declaration/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP009",
	"ruff_linter": "pyupgrade",
	"ruff_name": "utf8-encoding-declaration",
	"ruff_since": "v0.0.155",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^#\s*-\*-\s*coding:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "UTF-8 encoding declaration is unnecessary",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
