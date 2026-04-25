# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI042 (flake8-pyi): snake case type alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi042

import rego.v1

metadata := {
	"id": "RUFF-PYI042",
	"name": "snake case type alias",
	"description": "Type alias `<value>` should be CamelCase",
	"help_uri": "https://docs.astral.sh/ruff/rules/snake-case-type-alias/",
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
	"ruff_code": "PYI042",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "snake-case-type-alias",
	"ruff_since": "v0.0.265",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[A-Z][A-Z_]*\s*=\s*TypeVar`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "CamelCase TypeVar name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
