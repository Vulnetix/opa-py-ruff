# SPDX-License-Identifier: Apache-2.0
# Ruff rule B009 (flake8-bugbear): get attr with constant
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b009

import rego.v1

metadata := {
	"id": "RUFF-B009",
	"name": "get attr with constant",
	"description": "Do not call `getattr` with a constant attribute value. It is not any safer than normal property access.",
	"help_uri": "https://docs.astral.sh/ruff/rules/get-attr-with-constant/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B009",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "get-attr-with-constant",
	"ruff_since": "v0.0.110",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bgetattr\s*\([^,]+,\s*["\'][^"\']+["\'](?!\s*,)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Do not call getattr with a constant attribute value",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
