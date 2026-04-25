# SPDX-License-Identifier: Apache-2.0
# Ruff rule PD003 (pandas-vet): pandas use of dot is null
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_pd003

import rego.v1

metadata := {
	"id": "RUFF-PD003",
	"name": "pandas use of dot is null",
	"description": "`.isna` is preferred to `.isnull`; functionality is equivalent",
	"help_uri": "https://docs.astral.sh/ruff/rules/pandas-use-of-dot-is-null/",
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
	"ruff_code": "PD003",
	"ruff_linter": "pandas-vet",
	"ruff_name": "pandas-use-of-dot-is-null",
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
	regex.match(`\.isnull\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use .isna() instead of .isnull()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
