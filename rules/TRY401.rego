# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY401 (tryceratops): verbose log message
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try401

import rego.v1

metadata := {
	"id": "RUFF-TRY401",
	"name": "verbose log message",
	"description": "Redundant exception object included in `logging.exception` call",
	"help_uri": "https://docs.astral.sh/ruff/rules/verbose-log-message/",
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
	"ruff_code": "TRY401",
	"ruff_linter": "tryceratops",
	"ruff_name": "verbose-log-message",
	"ruff_since": "v0.0.250",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`logging\.exception\s*\(.*exc_info=True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Redundant exc_info=True in logging.exception()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
