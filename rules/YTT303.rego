# SPDX-License-Identifier: Apache-2.0
# Ruff rule YTT303 (flake8-2020): sys version slice1
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ytt303

import rego.v1

metadata := {
	"id": "RUFF-YTT303",
	"name": "sys version slice1",
	"description": "`sys.version[:1]` referenced (python10), use `sys.version_info`",
	"help_uri": "https://docs.astral.sh/ruff/rules/sys-version-slice1/",
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
	"ruff_code": "YTT303",
	"ruff_linter": "flake8-2020",
	"ruff_name": "sys-version-slice1",
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
	regex.match(`sys\.version_info\[1\]\s*[<>]=?\s*\d`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "sys.version_info[1] comparison on Python 2",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
