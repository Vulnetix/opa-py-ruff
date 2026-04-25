# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR1714 (Pylint): repeated equality comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr1714

import rego.v1

metadata := {
	"id": "RUFF-PLR1714",
	"name": "repeated equality comparison",
	"description": "Consider merging multiple comparisons: `<value>`. Use a `set` if the elements are hashable.",
	"help_uri": "https://docs.astral.sh/ruff/rules/repeated-equality-comparison/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plr"],
	"ruff_code": "PLR1714",
	"ruff_linter": "Pylint",
	"ruff_name": "repeated-equality-comparison",
	"ruff_since": "v0.0.279",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*!=\s*\w+\s+and\s+\w+\s*!=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Consider merging these comparisons with in",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
