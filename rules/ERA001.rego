# SPDX-License-Identifier: Apache-2.0
# Ruff rule ERA001 (eradicate): commented out code
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_era001

import rego.v1

metadata := {
	"id": "RUFF-ERA001",
	"name": "commented out code",
	"description": "Found commented-out code",
	"help_uri": "https://docs.astral.sh/ruff/rules/commented-out-code/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "eradicate", "era"],
	"ruff_code": "ERA001",
	"ruff_linter": "eradicate",
	"ruff_name": "commented-out-code",
	"ruff_since": "v0.0.145",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#.*(?:import|def |class |if |for |while |return )`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Commented-out code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
