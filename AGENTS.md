# AGENTS.md

## Cursor Cloud specific instructions

This is a pure-Python project with **zero external dependencies** (stdlib only). Python 3.10+ is required.

### Running the application

```bash
python3 demo.py
```

See `README.md` for feature coverage and project structure.

### Linting

No formal linter is configured in the repo. Use `py_compile` or `pyflakes` for basic checks:

```bash
python3 -m py_compile demo.py
python3 -m pyflakes demo.py queue_platform/
```

### Testing

No automated test suite exists yet. Verify correctness by running `python3 demo.py` and checking that wallboard, queue monitor, performance metrics, and AI routing preview output are printed without errors.

### Key caveats

- All state is in-memory; there are no databases, Docker containers, or external services to manage.
- The codebase uses modern Python syntax (`slots=True` dataclasses, `X | Y` union types, `datetime.UTC`) so Python < 3.10 will fail with syntax errors.
