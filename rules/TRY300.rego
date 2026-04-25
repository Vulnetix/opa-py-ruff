# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY300 (tryceratops): try consider else
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try300

import rego.v1

metadata := {
	"id": "RUFF-TRY300",
	"name": "try consider else",
	"description": "Consider moving this statement to an `else` block",
	"help_uri": "https://docs.astral.sh/ruff/rules/try-consider-else/",
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
	"ruff_code": "TRY300",
	"ruff_linter": "tryceratops",
	"ruff_name": "try-consider-else",
	"ruff_since": "v0.0.229",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`try:\s*\n.*return`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Consider moving return to else block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
