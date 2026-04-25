# SPDX-License-Identifier: Apache-2.0
# Ruff rule W291 (pycodestyle): trailing whitespace
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_w291

import rego.v1

metadata := {
	"id": "RUFF-W291",
	"name": "trailing whitespace",
	"description": "Trailing whitespace",
	"help_uri": "https://docs.astral.sh/ruff/rules/trailing-whitespace/",
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
	"ruff_code": "W291",
	"ruff_linter": "pycodestyle",
	"ruff_name": "trailing-whitespace",
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
	regex.match(`[ \t]+$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Trailing whitespace",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
