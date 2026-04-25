# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP012 (pyupgrade): unnecessary encode utf8
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up012

import rego.v1

metadata := {
	"id": "RUFF-UP012",
	"name": "unnecessary encode utf8",
	"description": "Unnecessary call to `encode` as UTF-8",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-encode-utf8/",
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
	"ruff_code": "UP012",
	"ruff_linter": "pyupgrade",
	"ruff_name": "unnecessary-encode-utf8",
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
	regex.match(`\.encode\s*\(\s*["\']utf-?8["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary call to encode() for UTF-8",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
