# SPDX-License-Identifier: Apache-2.0
# Ruff rule PD015 (pandas-vet): pandas use of pd merge
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pd015

import rego.v1

metadata := {
	"id": "RUFF-PD015",
	"name": "pandas use of pd merge",
	"description": "Use `.merge` method instead of `pd.merge` function. They have equivalent functionality.",
	"help_uri": "https://docs.astral.sh/ruff/rules/pandas-use-of-pd-merge/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pandas-vet", "pd"],
	"ruff_code": "PD015",
	"ruff_linter": "pandas-vet",
	"ruff_name": "pandas-use-of-pd-merge",
	"ruff_since": "v0.0.188",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`pd\.merge\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use df.merge() instead of pd.merge()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
