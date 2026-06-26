# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check that source files under this package carry the required notice header.

Scoped to the sd_cwt package so it does not affect the CCF-derived scaffold
files elsewhere in the repo (which keep their original Apache-2.0 headers).
"""

import os
import sys

NOTICE_LINES = [
    "Copyright (c) Microsoft Corporation.",
    "Licensed under the MIT License.",
]
_HEADER = "\n".join("# " + line for line in NOTICE_LINES)

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXCLUDE_DIRS = {".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "build"}
SUFFIXES = (".py", ".sh")


def has_notice(path: str) -> bool:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if text.startswith("#!"):  # allow a shebang before the notice
        text = text.split("\n", 1)[1] if "\n" in text else ""
    return text.startswith(_HEADER)


def main() -> int:
    missing = []
    for dirpath, dirnames, filenames in os.walk(PKG_ROOT):
        dirnames[:] = [
            d for d in dirnames if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")
        ]
        for name in filenames:
            if name.endswith(SUFFIXES):
                path = os.path.join(dirpath, name)
                if not has_notice(path):
                    missing.append(os.path.relpath(path, PKG_ROOT))
    if missing:
        print("Missing notice header in:")
        for m in sorted(missing):
            print("  " + m)
        return 1
    print("All files carry the notice header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
