# Development Guide

## Setup

```bash
git clone https://github.com/arkanzasfeziii/BlackForge.git
cd BlackForge
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Commands

```bash
make lint        # Run ruff linter
make format      # Auto-format code
make test        # Run all tests
make test-cov    # Tests with coverage report
make clean       # Remove caches
```

## Code Style

- Python 3.10+ with `from __future__ import annotations`
- Type hints on all function signatures
- PEP 8 via ruff
- Max line length: 120 characters
- Imports sorted by ruff (isort rules)

## Testing

Tests live in `tests/` and use pytest:

```bash
pytest tests/ -v                           # Run all
pytest tests/test_secrets.py -v            # Run specific file
pytest tests/ --cov=blackforge             # With coverage
```

## Project Layout Convention

| Directory | Contains |
|-----------|----------|
| `blackforge/modules/` | Attack modules (one per platform) |
| `blackforge/utils/` | Shared utilities (HTTP, secrets) |
| `blackforge/data/` | Static data (payloads, creds, endpoints) |
| `tests/` | Unit and integration tests |
| `docs/` | Documentation |
| `examples/` | Usage examples |
