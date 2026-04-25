# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE2513 (Pylint): invalid character esc
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple2513

import rego.v1

metadata := {
	"id": "RUFF-PLE2513",
	"name": "invalid character esc",
	"description": "Invalid unescaped character ESC, use '\x1b' instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-character-esc/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE2513",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-character-esc",
	"ruff_since": "v0.0.257",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\\\t`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Invalid line continuation before tab",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
