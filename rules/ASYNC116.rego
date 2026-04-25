# SPDX-License-Identifier: Apache-2.0
# Ruff rule ASYNC116 (flake8-async): long sleep not forever
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_async116

import rego.v1

metadata := {
	"id": "RUFF-ASYNC116",
	"name": "long sleep not forever",
	"description": "`<value>.sleep()` with >24 hour interval should usually be `<value>.sleep_forever()`",
	"help_uri": "https://docs.astral.sh/ruff/rules/long-sleep-not-forever/",
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
	"ruff_code": "ASYNC116",
	"ruff_linter": "flake8-async",
	"ruff_name": "long-sleep-not-forever",
	"ruff_since": "0.13.0",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`asyncio\.sleep\s*\(\s*\d+\s*\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "asyncio.sleep() with long timeout",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
