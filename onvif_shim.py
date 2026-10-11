#!/usr/bin/env python3
"""Launcher for one camera's ONVIF shim service (see README.md).

Run with `python3 -I`: the script directory (the resolved release directory) is
added explicitly so only the pinned release's modules are importable.
"""

import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from shimlib.shim import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
