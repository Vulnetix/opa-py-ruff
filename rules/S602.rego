# SPDX-License-Identifier: Apache-2.0
# Ruff rule S602 (flake8-bandit): subprocess popen with shell equals true
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_s602

import rego.v1

metadata := {
	"id": "RUFF-S602",
	"name": "subprocess popen with shell equals true",
	"description": "`subprocess` call with `shell=True` seems safe, but may be changed in the future; consider rewriting without `shell`",
	"help_uri": "https://docs.astral.sh/ruff/rules/subprocess-popen-with-shell-equals-true/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bandit", "s", "security"],
	"ruff_code": "S602",
	"ruff_linter": "flake8-bandit",
	"ruff_name": "subprocess-popen-with-shell-equals-true",
	"ruff_since": "v0.0.262",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`subprocess\.[A-Za-z]+\s*\(.*shell\s*=\s*True`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "subprocess call with shell=True",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
