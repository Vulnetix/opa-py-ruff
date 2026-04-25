# SPDX-License-Identifier: Apache-2.0
# Ruff rule EM103 (flake8-errmsg): dot format in exception
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_em103

import rego.v1

metadata := {
	"id": "RUFF-EM103",
	"name": "dot format in exception",
	"description": "Exception must not use a `.format()` string directly, assign to variable first",
	"help_uri": "https://docs.astral.sh/ruff/rules/dot-format-in-exception/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-errmsg", "em"],
	"ruff_code": "EM103",
	"ruff_linter": "flake8-errmsg",
	"ruff_name": "dot-format-in-exception",
	"ruff_since": "v0.0.183",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`raise\s+\w+\s*\(\s*\w+\.format\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "str.format() as exception argument",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
