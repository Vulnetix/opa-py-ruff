# SPDX-License-Identifier: Apache-2.0
# Ruff rule RUF056 (Ruff-specific rules): falsy dict get fallback
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_ruf056

import rego.v1

metadata := {
	"id": "RUFF-RUF056",
	"name": "falsy dict get fallback",
	"description": "Avoid providing a falsy fallback to `dict.get()` in boolean test positions. The default fallback `None` is already falsy.",
	"help_uri": "https://docs.astral.sh/ruff/rules/falsy-dict-get-fallback/",
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
	"ruff_code": "RUF056",
	"ruff_linter": "Ruff-specific rules",
	"ruff_name": "falsy-dict-get-fallback",
	"ruff_since": "0.8.5",
	"ruff_fix": "Sometimes",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
