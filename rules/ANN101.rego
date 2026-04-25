# SPDX-License-Identifier: Apache-2.0
# Ruff rule ANN101 (flake8-annotations): missing type self
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ann101

import rego.v1

metadata := {
	"id": "RUFF-ANN101",
	"name": "missing type self",
	"description": "Missing type annotation for `<value>` in method",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-type-self/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-annotations", "ann"],
	"ruff_code": "ANN101",
	"ruff_linter": "flake8-annotations",
	"ruff_name": "missing-type-self",
	"ruff_since": "0.8.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\(\s*self(?!:)\s*[,)]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Missing type annotation for self",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
