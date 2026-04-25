# SPDX-License-Identifier: Apache-2.0
# Ruff rule CPY001 (flake8-copyright): missing copyright notice
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_cpy001

import rego.v1

metadata := {
	"id": "RUFF-CPY001",
	"name": "missing copyright notice",
	"description": "Missing copyright notice at top of file",
	"help_uri": "https://docs.astral.sh/ruff/rules/missing-copyright-notice/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-copyright", "cpy"],
	"ruff_code": "CPY001",
	"ruff_linter": "flake8-copyright",
	"ruff_name": "missing-copyright-notice",
	"ruff_since": "v0.0.273",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Missing copyright notice",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
