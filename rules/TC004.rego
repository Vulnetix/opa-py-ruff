# SPDX-License-Identifier: Apache-2.0
# Ruff rule TC004 (flake8-type-checking): runtime import in type checking block
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_tc004

import rego.v1

metadata := {
	"id": "RUFF-TC004",
	"name": "runtime import in type checking block",
	"description": "Move import `<value>` out of type-checking block. Import is used for more than type hinting.",
	"help_uri": "https://docs.astral.sh/ruff/rules/runtime-import-in-type-checking-block/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-type-checking", "tc"],
	"ruff_code": "TC004",
	"ruff_linter": "flake8-type-checking",
	"ruff_name": "runtime-import-in-type-checking-block",
	"ruff_since": "0.8.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`TYPE_CHECKING`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Move import out of TYPE_CHECKING block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
