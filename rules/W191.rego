# SPDX-License-Identifier: Apache-2.0
# Ruff rule W191 (pycodestyle): tab indentation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_w191

import rego.v1

metadata := {
	"id": "RUFF-W191",
	"name": "tab indentation",
	"description": "Indentation contains tabs",
	"help_uri": "https://docs.astral.sh/ruff/rules/tab-indentation/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pycodestyle", "w"],
	"ruff_code": "W191",
	"ruff_linter": "pycodestyle",
	"ruff_name": "tab-indentation",
	"ruff_since": "v0.0.254",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\t`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Indentation contains tabs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
