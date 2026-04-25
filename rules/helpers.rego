package vulnetix.ruff.helpers

import rego.v1

is_py(path) if endswith(path, ".py")
is_py(path) if endswith(path, ".pyw")

lines_of(path) := split(input.file_contents[path], "\n")

# Returns true when the line (lowercased) is not a comment-only line
not_comment(line) if not startswith(trim_space(line), "#")

# Strips leading whitespace
trim_space(s) := trim_left(s, " \t")

# Returns indentation depth (number of leading spaces)
indent(line) := count(regex.find_n(`^ *`, line, 1)[0])
