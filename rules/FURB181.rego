# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB181 (refurb): hashlib digest hex
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb181

import rego.v1

metadata := {
	"id": "RUFF-FURB181",
	"name": "hashlib digest hex",
	"description": "Use of hashlib's `.digest().hex()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/hashlib-digest-hex/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB181",
	"ruff_linter": "refurb",
	"ruff_name": "hashlib-digest-hex",
	"ruff_since": "0.5.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`hex\s*\(\s*hash\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use hash() directly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
