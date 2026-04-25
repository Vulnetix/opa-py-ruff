# SPDX-License-Identifier: Apache-2.0
# Ruff rule UP006 (pyupgrade): non pep585 annotation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_up006

import rego.v1

metadata := {
	"id": "RUFF-UP006",
	"name": "non pep585 annotation",
	"description": "Use `<value>` instead of `<value>` for type annotation",
	"help_uri": "https://docs.astral.sh/ruff/rules/non-pep585-annotation/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pyupgrade", "up"],
	"ruff_code": "UP006",
	"ruff_linter": "pyupgrade",
	"ruff_name": "non-pep585-annotation",
	"ruff_since": "v0.0.155",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`:\s*(Dict|List|Tuple|Set|Type|FrozenSet)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use PEP 585 built-in type annotations",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
