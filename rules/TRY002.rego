# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY002 (tryceratops): raise vanilla class
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try002

import rego.v1

metadata := {
	"id": "RUFF-TRY002",
	"name": "raise vanilla class",
	"description": "Create your own exception",
	"help_uri": "https://docs.astral.sh/ruff/rules/raise-vanilla-class/",
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
	"ruff_code": "TRY002",
	"ruff_linter": "tryceratops",
	"ruff_name": "raise-vanilla-class",
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
	regex.match(`raise\s+Exception\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Create your own exception",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
