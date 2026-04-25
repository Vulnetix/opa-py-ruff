# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLR1704 (Pylint): redefined argument from local
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plr1704

import rego.v1

metadata := {
	"id": "RUFF-PLR1704",
	"name": "redefined argument from local",
	"description": "Redefining argument with the local name `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/redefined-argument-from-local/",
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
	"ruff_code": "PLR1704",
	"ruff_linter": "Pylint",
	"ruff_name": "redefined-argument-from-local",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`def\s+\w+\s*\([^)]+\):\s*\n\s+\w+\s*=\s*\w+\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Redefining argument with local variable",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
