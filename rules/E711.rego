# SPDX-License-Identifier: Apache-2.0
# Ruff rule E711 (pycodestyle): none comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_e711

import rego.v1

metadata := {
	"id": "RUFF-E711",
	"name": "none comparison",
	"description": "Comparison to `None` should be `cond is None`",
	"help_uri": "https://docs.astral.sh/ruff/rules/none-comparison/",
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
	"ruff_code": "E711",
	"ruff_linter": "pycodestyle",
	"ruff_name": "none-comparison",
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
	regex.match(`[=!]=\s*None|None\s*[=!]=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Comparison to None (use `is` or `is not`)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
