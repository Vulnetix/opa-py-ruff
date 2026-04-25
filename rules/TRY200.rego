# SPDX-License-Identifier: Apache-2.0
# Ruff rule TRY200 (tryceratops): reraise no cause
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_try200

import rego.v1

metadata := {
	"id": "RUFF-TRY200",
	"name": "reraise no cause",
	"description": "Use `raise from` to specify exception cause",
	"help_uri": "https://docs.astral.sh/ruff/rules/reraise-no-cause/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "tryceratops", "try"],
	"ruff_code": "TRY200",
	"ruff_linter": "tryceratops",
	"ruff_name": "reraise-no-cause",
	"ruff_since": "v0.2.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
