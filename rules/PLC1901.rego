# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLC1901 (Pylint): compare to empty string
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plc1901

import rego.v1

metadata := {
	"id": "RUFF-PLC1901",
	"name": "compare to empty string",
	"description": "`<value>` can be simplified to `<value>` as an empty string is falsey",
	"help_uri": "https://docs.astral.sh/ruff/rules/compare-to-empty-string/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plc"],
	"ruff_code": "PLC1901",
	"ruff_linter": "Pylint",
	"ruff_name": "compare-to-empty-string",
	"ruff_since": "v0.0.255",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\w+\s*==\s*["\']["\']|\w+\s*!=\s*["\']["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Comparison to empty string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
