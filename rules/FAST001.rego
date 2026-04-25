# SPDX-License-Identifier: Apache-2.0
# Ruff rule FAST001 (FastAPI): fast api redundant response model
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fast001

import rego.v1

metadata := {
	"id": "RUFF-FAST001",
	"name": "fast api redundant response model",
	"description": "FastAPI route with redundant `response_model` argument",
	"help_uri": "https://docs.astral.sh/ruff/rules/fast-api-redundant-response-model/",
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
	"ruff_code": "FAST001",
	"ruff_linter": "FastAPI",
	"ruff_name": "fast-api-redundant-response-model",
	"ruff_since": "0.8.0",
	"ruff_fix": "Always",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`@app\.(get|post|put|delete|patch)\s*\([^)]*response_model=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "FastAPI response model",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
