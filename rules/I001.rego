# SPDX-License-Identifier: Apache-2.0
# Ruff rule I001 (isort): unsorted imports
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_i001

import rego.v1

metadata := {
	"id": "RUFF-I001",
	"name": "unsorted imports",
	"description": "Import block is un-sorted or un-formatted",
	"help_uri": "https://docs.astral.sh/ruff/rules/unsorted-imports/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "isort", "i"],
	"ruff_code": "I001",
	"ruff_linter": "isort",
	"ruff_name": "unsorted-imports",
	"ruff_since": "v0.0.110",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^(from|import)\s+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Import block is incorrectly sorted",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
