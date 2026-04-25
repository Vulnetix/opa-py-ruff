# SPDX-License-Identifier: Apache-2.0
# Ruff rule LOG007 (flake8-logging): exception without exc info
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_log007

import rego.v1

metadata := {
	"id": "RUFF-LOG007",
	"name": "exception without exc info",
	"description": "Use of `logging.exception` with falsy `exc_info`",
	"help_uri": "https://docs.astral.sh/ruff/rules/exception-without-exc-info/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-logging", "log"],
	"ruff_code": "LOG007",
	"ruff_linter": "flake8-logging",
	"ruff_name": "exception-without-exc-info",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`logging\.exception\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use of logging.exception outside exception handler",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
