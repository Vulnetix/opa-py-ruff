# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLE1310 (Pylint): bad str strip call
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ple1310

import rego.v1

metadata := {
	"id": "RUFF-PLE1310",
	"name": "bad str strip call",
	"description": "String `<value>` call contains duplicate characters (did you mean `<value>`?)",
	"help_uri": "https://docs.astral.sh/ruff/rules/bad-str-strip-call/",
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
	"ruff_code": "PLE1310",
	"ruff_linter": "Pylint",
	"ruff_name": "bad-str-strip-call",
	"ruff_since": "v0.0.242",
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
		"message": ".strip() with chars not in ASCII",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
