# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB116 (refurb): f string number format
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb116

import rego.v1

metadata := {
	"id": "RUFF-FURB116",
	"name": "f string number format",
	"description": "Replace `<value>` call with `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/f-string-number-format/",
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
	"ruff_code": "FURB116",
	"ruff_linter": "refurb",
	"ruff_name": "f-string-number-format",
	"ruff_since": "0.13.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`format\s*\(\s*\w+\s*,\s*["\'][#x<>^0-9]+["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use int.to_bytes() instead of format()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
