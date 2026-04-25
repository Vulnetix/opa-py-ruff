# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW3301 (Pylint): nested min max
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw3301

import rego.v1

metadata := {
	"id": "RUFF-PLW3301",
	"name": "nested min max",
	"description": "Nested `<value>` calls can be flattened",
	"help_uri": "https://docs.astral.sh/ruff/rules/nested-min-max/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW3301",
	"ruff_linter": "Pylint",
	"ruff_name": "nested-min-max",
	"ruff_since": "v0.0.266",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`nested\s+min\s*\(|nested\s+max\s*\(|min\s*\(.*min\s*\(|max\s*\(.*max\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Nested min/max calls",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
