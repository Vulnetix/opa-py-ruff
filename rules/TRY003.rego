# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY003 (tryceratops): raise vanilla args
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try003

import rego.v1

metadata := {
	"id": "RUFF-TRY003",
	"name": "raise vanilla args",
	"description": "Avoid specifying long messages outside the exception class",
	"help_uri": "https://docs.astral.sh/ruff/rules/raise-vanilla-args/",
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
	"ruff_code": "TRY003",
	"ruff_linter": "tryceratops",
	"ruff_name": "raise-vanilla-args",
	"ruff_since": "v0.0.236",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`raise\s+\w+\s*\(\s*[f"\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid specifying long messages outside the exception class",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
