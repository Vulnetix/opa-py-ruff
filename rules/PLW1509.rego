# SPDX-License-Identifier: Apache-2.0
# Ruff rule PLW1509 (Pylint): subprocess popen preexec fn
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_plw1509

import rego.v1

metadata := {
	"id": "RUFF-PLW1509",
	"name": "subprocess popen preexec fn",
	"description": "`preexec_fn` argument is unsafe when using threads",
	"help_uri": "https://docs.astral.sh/ruff/rules/subprocess-popen-preexec-fn/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "pylint", "plw"],
	"ruff_code": "PLW1509",
	"ruff_linter": "Pylint",
	"ruff_name": "subprocess-popen-preexec-fn",
	"ruff_since": "v0.0.281",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`signal\.signal\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "signal.signal() for SIGTERM or SIGKILL",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
