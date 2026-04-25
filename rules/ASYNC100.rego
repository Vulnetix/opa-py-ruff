# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC100 (flake8-async): cancel scope no checkpoint
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async100

import rego.v1

metadata := {
	"id": "RUFF-ASYNC100",
	"name": "cancel scope no checkpoint",
	"description": "A `with <value>(...):` context does not contain any `await` statements. This makes it pointless, as the timeout can only be triggered by a checkpoint.",
	"help_uri": "https://docs.astral.sh/ruff/rules/cancel-scope-no-checkpoint/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-async", "async"],
	"ruff_code": "ASYNC100",
	"ruff_linter": "flake8-async",
	"ruff_name": "cancel-scope-no-checkpoint",
	"ruff_since": "v0.0.269",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`async\s+def.*:\s*\n.*time\.sleep\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "time.sleep() in async function",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
