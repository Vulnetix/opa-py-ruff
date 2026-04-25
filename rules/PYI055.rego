# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI055 (flake8-pyi): unnecessary type union
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi055

import rego.v1

metadata := {
	"id": "RUFF-PYI055",
	"name": "unnecessary type union",
	"description": "Multiple `type` members in a union. Combine them into one, e.g., `type[<value>]`.",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-type-union/",
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
	"ruff_code": "PYI055",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unnecessary-type-union",
	"ruff_since": "v0.0.283",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Union\[None,`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Redundant Union with None",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
