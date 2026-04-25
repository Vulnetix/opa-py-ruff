# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1142 (Pylint): await outside async
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1142

import rego.v1

metadata := {
	"id": "RUFF-PLE1142",
	"name": "await outside async",
	"description": "`await` should be used within an async function",
	"help_uri": "https://docs.astral.sh/ruff/rules/await-outside-async/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE1142",
	"ruff_linter": "Pylint",
	"ruff_name": "await-outside-async",
	"ruff_since": "v0.0.150",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`await\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "await outside async function",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
