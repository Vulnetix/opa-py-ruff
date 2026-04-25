# SPDX-License-Identifier: Apache-2.0
# Ruff rule B005 (flake8-bugbear): strip with multi characters
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b005

import rego.v1

metadata := {
	"id": "RUFF-B005",
	"name": "strip with multi characters",
	"description": "Using `.strip()` with multi-character strings is misleading",
	"help_uri": "https://docs.astral.sh/ruff/rules/strip-with-multi-characters/",
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
	"ruff_code": "B005",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "strip-with-multi-characters",
	"ruff_since": "v0.0.106",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.strip\s*\(\s*["\'][^"\']{2,}["\']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": ".strip() with multi-char string — use .lstrip()/.rstrip()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
