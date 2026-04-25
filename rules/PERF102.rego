# SPDX-License-Identifier: Apache-2.0
# Ruff rule PERF102 (Perflint): incorrect dict iterator
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_perf102

import rego.v1

metadata := {
	"id": "RUFF-PERF102",
	"name": "incorrect dict iterator",
	"description": "When using only the <value> of a dict use the `<value>()` method",
	"help_uri": "https://docs.astral.sh/ruff/rules/incorrect-dict-iterator/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "perflint", "perf"],
	"ruff_code": "PERF102",
	"ruff_linter": "Perflint",
	"ruff_name": "incorrect-dict-iterator",
	"ruff_since": "v0.0.273",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+,\s*\w+\s+in\s+\w+\.items\(\):\s*\n(?!.*\2)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "When using only the values of a dict, use dict.values()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
