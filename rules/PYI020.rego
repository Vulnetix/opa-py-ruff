# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI020 (flake8-pyi): quoted annotation in stub
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi020

import rego.v1

metadata := {
	"id": "RUFF-PYI020",
	"name": "quoted annotation in stub",
	"description": "Quoted annotations should not be included in stubs",
	"help_uri": "https://docs.astral.sh/ruff/rules/quoted-annotation-in-stub/",
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
	"ruff_code": "PYI020",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "quoted-annotation-in-stub",
	"ruff_since": "v0.0.265",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`Type\[Type\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Quoted annotation for non-string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
