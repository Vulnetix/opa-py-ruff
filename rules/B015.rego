# SPDX-License-Identifier: Apache-2.0
# Ruff rule B015 (flake8-bugbear): useless comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b015

import rego.v1

metadata := {
	"id": "RUFF-B015",
	"name": "useless comparison",
	"description": "Pointless comparison. Did you mean to assign a value? Otherwise, prepend `assert` or remove it.",
	"help_uri": "https://docs.astral.sh/ruff/rules/useless-comparison/",
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
	"ruff_code": "B015",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "useless-comparison",
	"ruff_since": "v0.0.102",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?<!=)\s*(==|!=|<=|>=|<|>)\s*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Pointless comparison",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
