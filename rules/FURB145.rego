# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB145 (refurb): slice copy
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb145

import rego.v1

metadata := {
	"id": "RUFF-FURB145",
	"name": "slice copy",
	"description": "Prefer `copy` method over slicing",
	"help_uri": "https://docs.astral.sh/ruff/rules/slice-copy/",
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
	"ruff_code": "FURB145",
	"ruff_linter": "refurb",
	"ruff_name": "slice-copy",
	"ruff_since": "v0.0.290",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\[:\]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use copy() instead of [:]",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
