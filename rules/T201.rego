# SPDX-License-Identifier: Apache-2.0
# Ruff rule T201 (flake8-print): print
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_t201

import rego.v1

metadata := {
	"id": "RUFF-T201",
	"name": "print",
	"description": "`print` found",
	"help_uri": "https://docs.astral.sh/ruff/rules/print/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-print", "t"],
	"ruff_code": "T201",
	"ruff_linter": "flake8-print",
	"ruff_name": "print",
	"ruff_since": "v0.0.57",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bprint\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "print() found",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
