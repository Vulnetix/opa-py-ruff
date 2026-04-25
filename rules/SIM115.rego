# SPDX-License-Identifier: Apache-2.0
# Ruff rule SIM115 (flake8-simplify): open file with context handler
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_sim115

import rego.v1

metadata := {
	"id": "RUFF-SIM115",
	"name": "open file with context handler",
	"description": "Use a context manager for opening files",
	"help_uri": "https://docs.astral.sh/ruff/rules/open-file-with-context-handler/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-simplify", "sim"],
	"ruff_code": "SIM115",
	"ruff_linter": "flake8-simplify",
	"ruff_name": "open-file-with-context-handler",
	"ruff_since": "v0.0.219",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bopen\s*\((?!.*with\b)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use context handler for opening files",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
