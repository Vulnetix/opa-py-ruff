# SPDX-License-Identifier: Apache-2.0
# Ruff rule FAST003 (FastAPI): fast api unused path parameter
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_fast003

import rego.v1

metadata := {
	"id": "RUFF-FAST003",
	"name": "fast api unused path parameter",
	"description": "Parameter `<value>` appears in route path, but not in `<value>` signature",
	"help_uri": "https://docs.astral.sh/ruff/rules/fast-api-unused-path-parameter/",
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
	"ruff_code": "FAST003",
	"ruff_linter": "FastAPI",
	"ruff_name": "fast-api-unused-path-parameter",
	"ruff_since": "0.10.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`@app\.route\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Use FastAPI decorators instead of @app.route",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
