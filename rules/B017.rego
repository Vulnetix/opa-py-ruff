# SPDX-License-Identifier: Apache-2.0
# Ruff rule B017 (flake8-bugbear): assert raises exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b017

import rego.v1

metadata := {
	"id": "RUFF-B017",
	"name": "assert raises exception",
	"description": "Do not assert blind exception: `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/assert-raises-exception/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B017",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "assert-raises-exception",
	"ruff_since": "v0.0.83",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`pytest\.raises\s*\(\s*Exception\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "pytest.raises(Exception) is too broad",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
