# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB129 (refurb): readlines in for
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb129

import rego.v1

metadata := {
	"id": "RUFF-FURB129",
	"name": "readlines in for",
	"description": "Instead of calling `readlines()`, iterate over file object directly",
	"help_uri": "https://docs.astral.sh/ruff/rules/readlines-in-for/",
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
	"ruff_code": "FURB129",
	"ruff_linter": "refurb",
	"ruff_name": "readlines-in-for",
	"ruff_since": "0.5.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`open\s*\([^)]+\)\s*\.readlines\s*\(\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use list(file) instead of file.readlines()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
