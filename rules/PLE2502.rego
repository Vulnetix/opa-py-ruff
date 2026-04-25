# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE2502 (Pylint): bidirectional unicode
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple2502

import rego.v1

metadata := {
	"id": "RUFF-PLE2502",
	"name": "bidirectional unicode",
	"description": "Contains control characters that can permit obfuscated code",
	"help_uri": "https://docs.astral.sh/ruff/rules/bidirectional-unicode/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "ple"],
	"ruff_code": "PLE2502",
	"ruff_linter": "Pylint",
	"ruff_name": "bidirectional-unicode",
	"ruff_since": "v0.0.244",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`[​-‏‪-‮⁠-⁯]`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Contains control characters",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
