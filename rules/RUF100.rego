# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF100 (Ruff-specific rules): unused noqa
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf100

import rego.v1

metadata := {
	"id": "RUFF-RUF100",
	"name": "unused noqa",
	"description": "Unused {}",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-noqa/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF100",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unused-noqa",
	"ruff_since": "v0.0.155",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`#\s*noqa\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "# noqa directive may be unused",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
