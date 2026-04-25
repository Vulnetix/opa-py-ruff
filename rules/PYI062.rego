# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI062 (flake8-pyi): duplicate literal member
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi062

import rego.v1

metadata := {
	"id": "RUFF-PYI062",
	"name": "duplicate literal member",
	"description": "Duplicate literal member `{}`",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-literal-member/",
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
	"ruff_code": "PYI062",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "duplicate-literal-member",
	"ruff_since": "0.6.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bLiteral\b.*Literal\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate Literal member",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
