# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF006 (Ruff-specific rules): asyncio dangling task
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf006

import rego.v1

metadata := {
	"id": "RUFF-RUF006",
	"name": "asyncio dangling task",
	"description": "Store a reference to the return value of `<value>.<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/asyncio-dangling-task/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF006",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "asyncio-dangling-task",
	"ruff_since": "v0.0.247",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`asyncio\.ensure_future\s*\(|loop\.create_task\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Store a reference to the event loop task",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
