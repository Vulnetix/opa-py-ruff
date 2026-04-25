# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY004 (tryceratops): type check without type error
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try004

import rego.v1

metadata := {
	"id": "RUFF-TRY004",
	"name": "type check without type error",
	"description": "Prefer `TypeError` exception for invalid type",
	"help_uri": "https://docs.astral.sh/ruff/rules/type-check-without-type-error/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "tryceratops", "try"],
	"ruff_code": "TRY004",
	"ruff_linter": "tryceratops",
	"ruff_name": "type-check-without-type-error",
	"ruff_since": "v0.0.230",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s+\w+.*TypeError`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Prefer TypeError for wrong type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
