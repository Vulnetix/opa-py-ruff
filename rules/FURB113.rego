# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB113 (refurb): repeated append
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb113

import rego.v1

metadata := {
	"id": "RUFF-FURB113",
	"name": "repeated append",
	"description": "Use `<value>` instead of repeatedly calling `<value>.append()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/repeated-append/",
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
	"ruff_code": "FURB113",
	"ruff_linter": "refurb",
	"ruff_name": "repeated-append",
	"ruff_since": "v0.0.287",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+\w+:\s*\n\s+\w+\.append\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use list.extend() instead of list.append() in loop",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
