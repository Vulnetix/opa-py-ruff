# SPDX-License-Identifier: Apache-2.0
# Ruff rule PERF101 (Perflint): unnecessary list cast
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_perf101

import rego.v1

metadata := {
	"id": "RUFF-PERF101",
	"name": "unnecessary list cast",
	"description": "Do not cast an iterable to `list` before iterating over it",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-list-cast/",
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
	"ruff_code": "PERF101",
	"ruff_linter": "Perflint",
	"ruff_name": "unnecessary-list-cast",
	"ruff_since": "v0.0.276",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`for\s+\w+\s+in\s+list\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not cast an iterable to a list before iterating over it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
