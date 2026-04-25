# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM300 (flake8-simplify): yoda conditions
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim300

import rego.v1

metadata := {
	"id": "RUFF-SIM300",
	"name": "yoda conditions",
	"description": "Yoda condition detected",
	"help_uri": "https://docs.astral.sh/ruff/rules/yoda-conditions/",
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
	"ruff_code": "SIM300",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "yoda-conditions",
	"ruff_since": "v0.0.207",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`None\s*==\s*\w+|\w+\s*==\s*None`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Yoda condition detected",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
