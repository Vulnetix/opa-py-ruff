# SPDX-License-Identifier: Apache-2.0
# Ruff rule RET503 (flake8-return): implicit return
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ret503

import rego.v1

metadata := {
	"id": "RUFF-RET503",
	"name": "implicit return",
	"description": "Missing explicit `return` at the end of function able to return non-`None` value",
	"help_uri": "https://docs.astral.sh/ruff/rules/implicit-return/",
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
	"ruff_code": "RET503",
	"ruff_linter": "flake8-return",
	"ruff_name": "implicit-return",
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
	regex.match(`def\s+\w+[^:]+:\s*\n`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Missing explicit return",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
