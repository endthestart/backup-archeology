# Contributing

Backup Archeology is intentionally conservative. A cleanup rule should be easy
to explain, test, and classify.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m py_compile ba.py tests/test_ba.py
```

## Rule Tiers

- `safe`: generated, cache, metadata, or runtime junk that is normally
  disposable from old backups.
- `review`: large, stateful, ambiguous, or high-consequence items that should be
  exported to a plan before deletion.

When in doubt, use `review`.

## Before Committing

- Do not commit local databases, manifests, logs, scan plans, cache folders, or
  editor/assistant state.
- Do not commit keys, credentials, machine names, personal paths, or backup
  listings from a real NAS.
- Add tests for new cleanup rules.
- Run the test suite and a CLI smoke test.
