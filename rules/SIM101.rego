# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM101 (flake8-simplify): duplicate isinstance call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim101

import rego.v1

metadata := {
	"id": "RUFF-SIM101",
	"name": "duplicate isinstance call",
	"description": "Multiple `isinstance` calls for `<value>`, merge into a single call",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-isinstance-call/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM101",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "duplicate-isinstance-call",
	"ruff_since": "v0.0.212",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`isinstance\s*\([^)]+\)\s*or\s*isinstance\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use a single isinstance() call with a tuple",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
