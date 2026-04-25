# SPDX-License-Identifier: Apache-2.0
# Ruff rule FURB161 (refurb): bit count
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_furb161

import rego.v1

metadata := {
	"id": "RUFF-FURB161",
	"name": "bit count",
	"description": "Use of `bin(<value>).count('1')`",
	"help_uri": "https://docs.astral.sh/ruff/rules/bit-count/",
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
	"ruff_code": "FURB161",
	"ruff_linter": "refurb",
	"ruff_name": "bit-count",
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
	regex.match(`\.bit_count\s*\(\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use bin(x).count(\"1\") instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
