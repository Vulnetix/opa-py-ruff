# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF010 (Ruff-specific rules): explicit f string type conversion
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf010

import rego.v1

metadata := {
	"id": "RUFF-RUF010",
	"name": "explicit f string type conversion",
	"description": "Use explicit conversion flag",
	"help_uri": "https://docs.astral.sh/ruff/rules/explicit-f-string-type-conversion/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF010",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "explicit-f-string-type-conversion",
	"ruff_since": "v0.0.267",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bstr\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use explicit conversion flag",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
