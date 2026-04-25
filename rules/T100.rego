# SPDX-License-Identifier: Apache-2.0
# Ruff rule T100 (flake8-debugger): debugger
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_t100

import rego.v1

metadata := {
	"id": "RUFF-T100",
	"name": "debugger",
	"description": "Trace found: `<value>` used",
	"help_uri": "https://docs.astral.sh/ruff/rules/debugger/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-debugger", "t"],
	"ruff_code": "T100",
	"ruff_linter": "flake8-debugger",
	"ruff_name": "debugger",
	"ruff_since": "v0.0.141",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bbreakpoint\s*\(|\bimport\s+pdb\b|\bpdb\.set_trace\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Debugger import/call detected",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
