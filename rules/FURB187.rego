# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB187 (refurb): list reverse copy
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb187

import rego.v1

metadata := {
	"id": "RUFF-FURB187",
	"name": "list reverse copy",
	"description": "Use of assignment of `reversed` on list `<value>`",
	"help_uri": "https://docs.astral.sh/ruff/rules/list-reverse-copy/",
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
	"ruff_code": "FURB187",
	"ruff_linter": "refurb",
	"ruff_name": "list-reverse-copy",
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
	regex.match(`list\s*\(\s*reversed\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use [::-1] instead of reversed()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
