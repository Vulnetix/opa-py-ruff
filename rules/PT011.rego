# SPDX-License-Identifier: Apache-2.0
# Ruff rule PT011 (flake8-pytest-style): pytest raises too broad
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pt011

import rego.v1

metadata := {
	"id": "RUFF-PT011",
	"name": "pytest raises too broad",
	"description": "`pytest.raises(<value>)` is too broad, set the `match` parameter or use a more specific exception",
	"help_uri": "https://docs.astral.sh/ruff/rules/pytest-raises-too-broad/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-pytest-style", "pt"],
	"ruff_code": "PT011",
	"ruff_linter": "flake8-pytest-style",
	"ruff_name": "pytest-raises-too-broad",
	"ruff_since": "v0.0.208",
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
