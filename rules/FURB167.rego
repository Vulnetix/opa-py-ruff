# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB167 (refurb): regex flag alias
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb167

import rego.v1

metadata := {
	"id": "RUFF-FURB167",
	"name": "regex flag alias",
	"description": "Use of regular expression alias `re.{}`",
	"help_uri": "https://docs.astral.sh/ruff/rules/regex-flag-alias/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "refurb", "furb"],
	"ruff_code": "FURB167",
	"ruff_linter": "refurb",
	"ruff_name": "regex-flag-alias",
	"ruff_since": "0.5.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`re\.(IGNORECASE|MULTILINE|DOTALL|VERBOSE)\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use flag literal instead of flag name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
