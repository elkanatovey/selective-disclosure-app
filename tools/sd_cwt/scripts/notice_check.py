# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check that source files in the sd_cwt package carry the required notice header.

Enumerates tracked files with ``git ls-files`` (as CCF/SCITT do), scoped to this
package so the CCF-derived scaffold elsewhere keeps its own Apache-2.0 headers.
"""

import os
import subprocess
import sys

NOTICE_LINES = [
    "Copyright (c) Microsoft Corporation.",
    "Licensed under the MIT License.",
]
HASH_PREFIXED = "\n".join("# " + line for line in NOTICE_LINES)

# Accepted header forms per file type (a shebang may precede the notice).
PREFIX_BY_SUFFIX = {
    ".py": [HASH_PREFIXED],
    ".sh": [HASH_PREFIXED],
}

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def has_notice(path, prefixes):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if text.startswith("#!"):  # allow a shebang before the notice
        text = text.split("\n", 1)[1] if "\n" in text else ""
    return any(text.startswith(p) for p in prefixes)


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], cwd=PKG_ROOT, capture_output=True, check=True
    ).stdout.decode()
    return out.splitlines()


def main():
    missing = []
    count = 0
    for rel in tracked_files():
        prefixes = PREFIX_BY_SUFFIX.get(os.path.splitext(rel)[1])
        if not prefixes:
            continue
        path = os.path.join(PKG_ROOT, rel)
        if not os.path.isfile(path):  # ignore moved/deleted entries
            continue
        count += 1
        if not has_notice(path, prefixes):
            missing.append(rel)

    print(f"Checked {count} files for notice headers.")
    for rel in sorted(missing):
        print(f"  missing: {rel}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
