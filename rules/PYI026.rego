# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI026 (flake8-pyi): type alias without annotation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi026

import rego.v1

metadata := {
	"id": "RUFF-PYI026",
	"name": "type alias without annotation",
	"description": "Use `<value>.TypeAlias` for type alias, e.g., `<value>: TypeAlias = <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-alias-without-annotation/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI026",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "type-alias-without-annotation",
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
	regex.match(`TypeAlias\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use type statement for TypeAlias",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
