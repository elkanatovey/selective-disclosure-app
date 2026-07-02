# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Repo-wide check that first-party source files carry the MIT notice header.

Enumerates tracked files with ``git ls-files`` (as CCF/SCITT do). The
``third_party/`` submodule keeps its own license and is skipped.
"""

import os
import subprocess
import sys

NOTICE_LINES = [
    "Copyright (c) Microsoft Corporation.",
    "Licensed under the MIT License.",
]
SLASH = "\n".join("// " + line for line in NOTICE_LINES)
HASH = "\n".join("# " + line for line in NOTICE_LINES)

# C/C++ headers carry the notice then `#pragma once` (optionally a blank between).
HEADERS_WITH_PRAGMA = [SLASH + "\n#pragma once", SLASH + "\n\n#pragma once"]

PREFIX_BY_SUFFIX = {
    ".c": [SLASH],
    ".cpp": [SLASH],
    ".h": HEADERS_WITH_PRAGMA,
    ".hpp": HEADERS_WITH_PRAGMA,
    ".py": [HASH],
    ".sh": [HASH],
    ".cmake": [HASH],
}
PREFIX_BY_NAME = {
    "CMakeLists.txt": [HASH],
    "Dockerfile": [HASH],
}

EXCLUDE_PREFIXES = ("third_party/",)


def repo_root():
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, check=True
    ).stdout.decode()
    return out.strip()


def tracked_files(root):
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, check=True
    ).stdout.decode()
    return out.splitlines()


def prefixes_for(rel):
    name = os.path.basename(rel)
    if name in PREFIX_BY_NAME:
        return PREFIX_BY_NAME[name]
    return PREFIX_BY_SUFFIX.get(os.path.splitext(rel)[1])


def has_notice(path, prefixes):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if text.startswith("#!"):  # allow a shebang before the notice
        text = text.split("\n", 1)[1] if "\n" in text else ""
    return any(text.startswith(p) for p in prefixes)


def main():
    root = repo_root()
    missing = []
    count = 0
    for rel in tracked_files(root):
        if rel.startswith(EXCLUDE_PREFIXES):
            continue
        prefixes = prefixes_for(rel)
        if not prefixes:
            continue
        path = os.path.join(root, rel)
        if not os.path.isfile(path):  # ignore moved/deleted entries
            continue
        count += 1
        if not has_notice(path, prefixes):
            missing.append(rel)

    print(f"Checked {count} files for the MIT notice header.")
    for rel in sorted(missing):
        print(f"  missing: {rel}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
