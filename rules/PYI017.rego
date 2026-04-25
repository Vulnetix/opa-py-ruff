# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI017 (flake8-pyi): complex assignment in stub
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi017

import rego.v1

metadata := {
	"id": "RUFF-PYI017",
	"name": "complex assignment in stub",
	"description": "Stubs should not contain assignments to attributes or multiple targets",
	"help_uri": "https://docs.astral.sh/ruff/rules/complex-assignment-in-stub/",
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
	"ruff_code": "PYI017",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "complex-assignment-in-stub",
	"ruff_since": "v0.0.279",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Union\[Union\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Duplicate Union[Union[x]]",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
