# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0133 (Pylint): comparison of constant
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0133

import rego.v1

metadata := {
	"id": "RUFF-PLR0133",
	"name": "comparison of constant",
	"description": "Two constants compared in a comparison, consider replacing `<value> <value> <value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/comparison-of-constant/",
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
	"ruff_code": "PLR0133",
	"ruff_linter": "Pylint",
	"ruff_name": "comparison-of-constant",
	"ruff_since": "v0.0.221",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\b\d+\s*[<>=!]=\s*\d+\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Comparison between two constant literals",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
