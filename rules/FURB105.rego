# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB105 (refurb): print empty string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb105

import rego.v1

metadata := {
	"id": "RUFF-FURB105",
	"name": "print empty string",
	"description": "Unnecessary empty string passed to `print`",
	"help_uri": "https://docs.astral.sh/ruff/rules/print-empty-string/",
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
	"ruff_code": "FURB105",
	"ruff_linter": "refurb",
	"ruff_name": "print-empty-string",
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
	regex.match(`"\s*\.join\s*\(\s*\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary list in str.join()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
