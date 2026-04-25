# SPDX-License-Identifier: Apache-2.0
# Ruff rule E721 (pycodestyle): type comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e721

import rego.v1

metadata := {
	"id": "RUFF-E721",
	"name": "type comparison",
	"description": "Use `is` and `is not` for type comparisons, or `isinstance()` for isinstance checks",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-comparison/",
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
	"ruff_code": "E721",
	"ruff_linter": "pycodestyle",
	"ruff_name": "type-comparison",
	"ruff_since": "v0.0.39",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\btype\s*\(.*\)\s*[=!]=\s*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use `isinstance()` for type comparison",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
