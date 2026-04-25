# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR5501 (Pylint): collapsible else if
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr5501

import rego.v1

metadata := {
	"id": "RUFF-PLR5501",
	"name": "collapsible else if",
	"description": "Use `elif` instead of `else` then `if`, to reduce indentation",
	"help_uri": "https://docs.astral.sh/ruff/rules/collapsible-else-if/",
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
	"ruff_code": "PLR5501",
	"ruff_linter": "Pylint",
	"ruff_name": "collapsible-else-if",
	"ruff_since": "v0.0.253",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+.+:\s*\n\s+.+\s*\nelif\s+.+:\s*\n\s+else:`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use elif instead of else: if:",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
