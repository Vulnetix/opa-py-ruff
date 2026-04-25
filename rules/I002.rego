# SPDX-License-Identifier: Apache-2.0
# Ruff rule I002 (isort): missing required import
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_i002

import rego.v1

metadata := {
	"id": "RUFF-I002",
	"name": "missing required import",
	"description": "Missing required import: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-required-import/",
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
	"ruff_code": "I002",
	"ruff_linter": "isort",
	"ruff_name": "missing-required-import",
	"ruff_since": "v0.0.218",
	"ruff_fix": "Always",
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
		"message": "Missing required import",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
