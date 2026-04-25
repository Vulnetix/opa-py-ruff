# SPDX-License-Identifier: Apache-2.0
# Ruff rule YTT103 (flake8-2020): sys version cmp str3
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ytt103

import rego.v1

metadata := {
	"id": "RUFF-YTT103",
	"name": "sys version cmp str3",
	"description": "`sys.version` compared to string (python3.10), use `sys.version_info`",
	"help_uri": "https://docs.astral.sh/ruff/rules/sys-version-cmp-str3/",
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
	"ruff_code": "YTT103",
	"ruff_linter": "flake8-2020",
	"ruff_name": "sys-version-cmp-str3",
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
	regex.match(`sys\.version\s*==`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "sys.version comparison should use sys.version_info",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
