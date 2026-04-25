# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR0124 (Pylint): comparison with itself
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr0124

import rego.v1

metadata := {
	"id": "RUFF-PLR0124",
	"name": "comparison with itself",
	"description": "Name compared with itself, consider replacing `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/comparison-with-itself/",
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
	"ruff_code": "PLR0124",
	"ruff_linter": "Pylint",
	"ruff_name": "comparison-with-itself",
	"ruff_since": "v0.0.273",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*==\s*\w+\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Name compared with itself",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
