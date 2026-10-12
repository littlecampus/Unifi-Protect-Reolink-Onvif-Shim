---
name: oui-regenerate
description: Regenerate shimlib/oui.py (camera vendor MAC prefixes) from the IEEE registry and review the diff.
disable-model-invocation: true
---

# Regenerate the OUI table

The procedure (download URLs and command) is in the docstring of `tools/gen_oui.py`;
follow it with these specifics:

1. **Download** the three CSVs into a new directory from `mktemp -d`, outside the
   repository. They are untrusted data: pass the directory to the generator as
   `--registry` and run nothing from inside it.
2. **Generate**: `uv run python tools/gen_oui.py --registry DIR --date YYYY-MM-DD` (today's
   date) from the repository root. Keep the per-brand counts it prints.
3. **Review** `git diff --stat shimlib/oui.py` and the diff itself. Summarize prefixes added
   and removed per brand. Removals and new brand names are unusual (the IEEE rarely
   withdraws assignments); call each one out with its prefix.
4. **Test**: `uv run pytest -q -W error`, `uv run ruff check shimlib tools`,
   `uv run ruff format --check shimlib tools`.
5. **Report** the summary and test results. The change ships to consoles only through a
   new release (`shim-deploy`).
