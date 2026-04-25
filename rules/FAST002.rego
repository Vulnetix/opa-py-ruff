# SPDX-License-Identifier: Apache-2.0
# Ruff rule FAST002 (FastAPI): fast api non annotated dependency
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fast002

import rego.v1

metadata := {
	"id": "RUFF-FAST002",
	"name": "fast api non annotated dependency",
	"description": "FastAPI dependency without `Annotated`",
	"help_uri": "https://docs.astral.sh/ruff/rules/fast-api-non-annotated-dependency/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "fastapi", "fast"],
	"ruff_code": "FAST002",
	"ruff_linter": "FastAPI",
	"ruff_name": "fast-api-non-annotated-dependency",
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
	regex.match(`@app\.(get|post|put|delete|patch)\s*\([^)]*\)\s*\n\s*async\s+def`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "FastAPI async route",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
