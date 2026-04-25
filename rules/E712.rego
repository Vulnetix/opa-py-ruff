# SPDX-License-Identifier: Apache-2.0
# Ruff rule E712 (pycodestyle): true false comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e712

import rego.v1

metadata := {
	"id": "RUFF-E712",
	"name": "true false comparison",
	"description": "Avoid equality comparisons to `True`; use `<value>:` for truth checks",
	"help_uri": "https://docs.astral.sh/ruff/rules/true-false-comparison/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "e"],
	"ruff_code": "E712",
	"ruff_linter": "pycodestyle",
	"ruff_name": "true-false-comparison",
	"ruff_since": "v0.0.28",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[=!]=\s*(True|False)|(True|False)\s*[=!]=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Comparison to True/False (use truthiness check)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
