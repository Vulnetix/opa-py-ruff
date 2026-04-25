# SPDX-License-Identifier: Apache-2.0
# Ruff rule TC005 (flake8-type-checking): empty type checking block
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tc005

import rego.v1

metadata := {
	"id": "RUFF-TC005",
	"name": "empty type checking block",
	"description": "Found empty type-checking block",
	"help_uri": "https://docs.astral.sh/ruff/rules/empty-type-checking-block/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-type-checking", "tc"],
	"ruff_code": "TC005",
	"ruff_linter": "flake8-type-checking",
	"ruff_name": "empty-type-checking-block",
	"ruff_since": "0.8.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`if\s+TYPE_CHECKING:\s*\n\s*\w+\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Delete empty TYPE_CHECKING block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
