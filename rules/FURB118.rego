# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB118 (refurb): reimplemented operator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb118

import rego.v1

metadata := {
	"id": "RUFF-FURB118",
	"name": "reimplemented operator",
	"description": "Use `operator.<value>` instead of defining a <value>",
	"help_uri": "https://docs.astral.sh/ruff/rules/reimplemented-operator/",
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
	"ruff_code": "FURB118",
	"ruff_linter": "refurb",
	"ruff_name": "reimplemented-operator",
	"ruff_since": "v0.1.9",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`lambda\s+[xy]\s*,\s*[xy]\s*:\s*\1\s*\+\s*\2`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use operator.add instead of lambda x, y: x + y",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
