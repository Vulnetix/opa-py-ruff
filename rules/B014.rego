# SPDX-License-Identifier: Apache-2.0
# Ruff rule B014 (flake8-bugbear): duplicate handler exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b014

import rego.v1

metadata := {
	"id": "RUFF-B014",
	"name": "duplicate handler exception",
	"description": "Exception handler with duplicate exception: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-handler-exception/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B014",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "duplicate-handler-exception",
	"ruff_since": "v0.0.67",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s*\(\s*\w+\s*,\s*\w+\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Redundant exception types",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
