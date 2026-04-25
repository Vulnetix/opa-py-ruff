# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY400 (tryceratops): error instead of exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try400

import rego.v1

metadata := {
	"id": "RUFF-TRY400",
	"name": "error instead of exception",
	"description": "Use `logging.exception` instead of `logging.error`",
	"help_uri": "https://docs.astral.sh/ruff/rules/error-instead-of-exception/",
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
	"ruff_code": "TRY400",
	"ruff_linter": "tryceratops",
	"ruff_name": "error-instead-of-exception",
	"ruff_since": "v0.0.236",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`except\s+.*:\s*\n\s+logging\.(warn|error|critical)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use logging.exception instead of logging.error",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
