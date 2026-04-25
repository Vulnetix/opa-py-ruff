# SPDX-License-Identifier: Apache-2.0
# Ruff rule B909 (flake8-bugbear): loop iterator mutation
# Clean-room Rego implementation for the Vulnetix CLI input model.

package vulnetix.rules.ruff_b909

import rego.v1

metadata := {
	"id": "RUFF-B909",
	"name": "loop iterator mutation",
	"description": "Mutation to loop iterable `<value>` during iteration",
	"help_uri": "https://docs.astral.sh/ruff/rules/loop-iterator-mutation/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["python", "ruff", "flake8-bugbear", "b"],
	"ruff_code": "B909",
	"ruff_linter": "flake8-bugbear",
	"ruff_name": "loop-iterator-mutation",
	"ruff_since": "v0.3.7",
	"ruff_fix": "None",
}

_is_py(path) if endswith(path, ".py")
_is_py(path) if endswith(path, ".pyw")

# NOTE: This rule requires AST-level analysis and cannot be fully implemented
# via text patterns. This is a stub that flags files for manual review.
# Full implementation would require a Python AST parser.

# Stub: no findings by default (requires AST analysis)
findings := set()
