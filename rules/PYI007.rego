# SPDX-License-Identifier: Apache-2.0
# Ruff rule PYI007 (flake8-pyi): unrecognized platform check
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pyi007

import rego.v1

metadata := {
	"id": "RUFF-PYI007",
	"name": "unrecognized platform check",
	"description": "Unrecognized `sys.platform` check",
	"help_uri": "https://docs.astral.sh/ruff/rules/unrecognized-platform-check/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pyi", "pyi"],
	"ruff_code": "PYI007",
	"ruff_linter": "flake8-pyi",
	"ruff_name": "unrecognized-platform-check",
	"ruff_since": "v0.0.246",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`typing\.overload\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "@typing.overload on function with implementation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
