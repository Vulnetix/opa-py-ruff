# SPDX-License-Identifier: Apache-2.0
# Ruff rule RET502 (flake8-return): implicit return value
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ret502

import rego.v1

metadata := {
	"id": "RUFF-RET502",
	"name": "implicit return value",
	"description": "Do not implicitly `return None` in function able to return non-`None` value",
	"help_uri": "https://docs.astral.sh/ruff/rules/implicit-return-value/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-return", "ret"],
	"ruff_code": "RET502",
	"ruff_linter": "flake8-return",
	"ruff_name": "implicit-return-value",
	"ruff_since": "v0.0.154",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`return\s*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Implicit return None",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
