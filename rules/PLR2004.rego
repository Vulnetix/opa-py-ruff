# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR2004 (Pylint): magic value comparison
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr2004

import rego.v1

metadata := {
	"id": "RUFF-PLR2004",
	"name": "magic value comparison",
	"description": "Magic value used in comparison, consider replacing `<value>` with a constant variable",
	"help_uri": "https://docs.astral.sh/ruff/rules/magic-value-comparison/",
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
	"ruff_code": "PLR2004",
	"ruff_linter": "Pylint",
	"ruff_name": "magic-value-comparison",
	"ruff_since": "v0.0.221",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[=!]=\s*\d+|[=!]=\s*["\'][^"\']{0,2}["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Magic value comparison",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
