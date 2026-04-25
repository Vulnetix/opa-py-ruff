# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE0116 (Pylint): continue in finally
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple0116

import rego.v1

metadata := {
	"id": "RUFF-PLE0116",
	"name": "continue in finally",
	"description": "`continue` not supported inside `finally` clause",
	"help_uri": "https://docs.astral.sh/ruff/rules/continue-in-finally/",
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
	"ruff_code": "PLE0116",
	"ruff_linter": "Pylint",
	"ruff_name": "continue-in-finally",
	"ruff_since": "v0.0.257",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`continue\s+#[^\n]*$`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "continue in finally block",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
