# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF015 (Ruff-specific rules): unnecessary iterable allocation for first element
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf015

import rego.v1

metadata := {
	"id": "RUFF-RUF015",
	"name": "unnecessary iterable allocation for first element",
	"description": "Prefer `next(<value>)` over single element slice",
	"help_uri": "https://docs.astral.sh/ruff/rules/unnecessary-iterable-allocation-for-first-element/",
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
	"ruff_code": "RUF015",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unnecessary-iterable-allocation-for-first-element",
	"ruff_since": "v0.0.278",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bnext\s*\(\s*iter\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Prefer next(iter(...)) over list(...)[0]",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
