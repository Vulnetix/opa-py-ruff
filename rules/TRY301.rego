# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY301 (tryceratops): raise within try
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try301

import rego.v1

metadata := {
	"id": "RUFF-TRY301",
	"name": "raise within try",
	"description": "Abstract `raise` to an inner function",
	"help_uri": "https://docs.astral.sh/ruff/rules/raise-within-try/",
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
	"ruff_code": "TRY301",
	"ruff_linter": "tryceratops",
	"ruff_name": "raise-within-try",
	"ruff_since": "v0.0.233",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`raise\s+\w+\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Abstract raise to inner function",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
