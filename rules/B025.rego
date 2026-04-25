# SPDX-License-Identifier: Apache-2.0
# Ruff rule B025 (flake8-bugbear): duplicate try block exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b025

import rego.v1

metadata := {
	"id": "RUFF-B025",
	"name": "duplicate try block exception",
	"description": "try-except* block with duplicate exception `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/duplicate-try-block-exception/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B025",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "duplicate-try-block-exception",
	"ruff_since": "v0.0.67",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s*\([^)]*,[^)]*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "try-except with duplicate exception types",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
