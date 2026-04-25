# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF005 (Ruff-specific rules): collection literal concatenation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf005

import rego.v1

metadata := {
	"id": "RUFF-RUF005",
	"name": "collection literal concatenation",
	"description": "Consider `<value>` instead of concatenation",
	"help_uri": "https://docs.astral.sh/ruff/rules/collection-literal-concatenation/",
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
	"ruff_code": "RUF005",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "collection-literal-concatenation",
	"ruff_since": "v0.0.227",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\[.*\]\s*\+\s*\[|\(\s*\*[^,)]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Consider iterable unpacking instead of concatenation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
