# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB168 (refurb): isinstance type none
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb168

import rego.v1

metadata := {
	"id": "RUFF-FURB168",
	"name": "isinstance type none",
	"description": "Prefer `is` operator over `isinstance` to check if an object is `None`",
	"help_uri": "https://docs.astral.sh/ruff/rules/isinstance-type-none/",
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
	"ruff_code": "FURB168",
	"ruff_linter": "refurb",
	"ruff_name": "isinstance-type-none",
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
	regex.match(`isinstance\s*\([^)]+,\s*type\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use isinstance() with type instead of type check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
