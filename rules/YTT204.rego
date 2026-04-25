# SPDX-License-Identifier: Apache-2.0
# Ruff rule YTT204 (flake8-2020): sys version info minor cmp int
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ytt204

import rego.v1

metadata := {
	"id": "RUFF-YTT204",
	"name": "sys version info minor cmp int",
	"description": "`sys.version_info.minor` compared to integer (python4), compare `sys.version_info` to tuple",
	"help_uri": "https://docs.astral.sh/ruff/rules/sys-version-info-minor-cmp-int/",
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
	"ruff_code": "YTT204",
	"ruff_linter": "flake8-2020",
	"ruff_name": "sys-version-info-minor-cmp-int",
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
	regex.match(`sys\.version_info\.minor\s*[<>]=?\s*\d`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "sys.version_info.minor comparison",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
