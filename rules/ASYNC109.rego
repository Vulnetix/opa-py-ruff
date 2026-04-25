# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC109 (flake8-async): async function with timeout
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async109

import rego.v1

metadata := {
	"id": "RUFF-ASYNC109",
	"name": "async function with timeout",
	"description": "Async function definition with a `timeout` parameter",
	"help_uri": "https://docs.astral.sh/ruff/rules/async-function-with-timeout/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-async", "async"],
	"ruff_code": "ASYNC109",
	"ruff_linter": "flake8-async",
	"ruff_name": "async-function-with-timeout",
	"ruff_since": "0.5.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`async\s+def\s+\w+\s*\([^)]*timeout\s*=\s*None`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Async function with unused timeout argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
