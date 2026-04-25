# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB132 (refurb): check and remove from set
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb132

import rego.v1

metadata := {
	"id": "RUFF-FURB132",
	"name": "check and remove from set",
	"description": "Use `<value>` instead of check and `remove`",
	"help_uri": "https://docs.astral.sh/ruff/rules/check-and-remove-from-set/",
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
	"ruff_code": "FURB132",
	"ruff_linter": "refurb",
	"ruff_name": "check-and-remove-from-set",
	"ruff_since": "0.12.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+\w+\s+in\s+\w+:\s*\n\s+\w+\.remove\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use set.discard() instead of conditional remove",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
