# SPDX-License-Identifier: Apache-2.0
# Ruff rule W292 (pycodestyle): missing newline at end of file
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_w292

import rego.v1

metadata := {
	"id": "RUFF-W292",
	"name": "missing newline at end of file",
	"description": "No newline at end of file",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-newline-at-end-of-file/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "w"],
	"ruff_code": "W292",
	"ruff_linter": "pycodestyle",
	"ruff_name": "missing-newline-at-end-of-file",
	"ruff_since": "v0.0.61",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[^\n]$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "No newline at end of file",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
