# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF029 (Ruff-specific rules): unused async
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf029

import rego.v1

metadata := {
	"id": "RUFF-RUF029",
	"name": "unused async",
	"description": "Function `<value>` is declared `async`, but doesn't `await` or use `async` features.",
	"help_uri": "https://docs.astral.sh/ruff/rules/unused-async/",
	"languages": ["python"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "ruff-specific-rules", "ruf"],
	"ruff_code": "RUF029",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "unused-async",
	"ruff_since": "v0.4.0",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
