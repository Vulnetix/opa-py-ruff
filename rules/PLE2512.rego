# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE2512 (Pylint): invalid character sub
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple2512

import rego.v1

metadata := {
	"id": "RUFF-PLE2512",
	"name": "invalid character sub",
	"description": "Invalid unescaped character SUB, use '\x1a' instead",
	"help_uri": "https://docs.astral.sh/ruff/rules/invalid-character-sub/",
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
	"ruff_code": "PLE2512",
	"ruff_linter": "Pylint",
	"ruff_name": "invalid-character-sub",
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
	regex.match(`^\s*\\$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Invalid line continuation at end of file",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
