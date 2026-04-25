# SPDX-License-Identifier: Apache-2.0
# Ruff rule YTT202 (flake8-2020): six py3
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ytt202

import rego.v1

metadata := {
	"id": "RUFF-YTT202",
	"name": "six py3",
	"description": "`six.PY3` referenced (python4), use `not six.PY2`",
	"help_uri": "https://docs.astral.sh/ruff/rules/six-py3/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-2020", "ytt"],
	"ruff_code": "YTT202",
	"ruff_linter": "flake8-2020",
	"ruff_name": "six-py3",
	"ruff_since": "v0.0.113",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`six\.PY3\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "six.PY3 is always True",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
