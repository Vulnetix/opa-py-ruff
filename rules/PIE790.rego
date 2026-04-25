# SPDX-License-Identifier: Apache-2.0
# Ruff rule PIE790 (flake8-pie): unnecessary placeholder
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pie790

import rego.v1

metadata := {
	"id": "RUFF-PIE790",
	"name": "unnecessary placeholder",
	"description": "Unnecessary `pass` statement",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-placeholder/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pie", "pie"],
	"ruff_code": "PIE790",
	"ruff_linter": "flake8-pie",
	"ruff_name": "unnecessary-placeholder",
	"ruff_since": "v0.0.208",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*\.\.\.\s*$|^\s*pass\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary ... or pass literal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
