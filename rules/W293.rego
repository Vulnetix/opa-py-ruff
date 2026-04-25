# SPDX-License-Identifier: Apache-2.0
# Ruff rule W293 (pycodestyle): blank line with whitespace
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_w293

import rego.v1

metadata := {
	"id": "RUFF-W293",
	"name": "blank line with whitespace",
	"description": "Blank line contains whitespace",
	"help_uri": "https://docs.astral.sh/ruff/rules/blank-line-with-whitespace/",
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
	"ruff_code": "W293",
	"ruff_linter": "pycodestyle",
	"ruff_name": "blank-line-with-whitespace",
	"ruff_since": "v0.0.253",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^[ \t]+$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Whitespace before a blank line",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
