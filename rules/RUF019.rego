# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF019 (Ruff-specific rules): unnecessary key check
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf019

import rego.v1

metadata := {
	"id": "RUFF-RUF019",
	"name": "unnecessary key check",
	"description": "Unnecessary key check before dictionary access",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-key-check/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF019",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unnecessary-key-check",
	"ruff_since": "v0.2.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bunnecessary_key_check\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Unnecessary key check before dictionary access",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
