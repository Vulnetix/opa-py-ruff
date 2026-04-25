# SPDX-License-Identifier: Apache-2.0
# Ruff rule B012 (flake8-bugbear): jump statement in finally
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b012

import rego.v1

metadata := {
	"id": "RUFF-B012",
	"name": "jump statement in finally",
	"description": "`<value>` inside `finally` blocks cause exceptions to be silenced",
	"help_uri": "https://docs.astral.sh/ruff/rules/jump-statement-in-finally/",
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
	"ruff_code": "B012",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "jump-statement-in-finally",
	"ruff_since": "v0.0.116",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\breturn\b.*\bfinally\b|\bfinally\b.*\breturn\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "return inside finally block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
