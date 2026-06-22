# Contributing to BlackForge

## Code of Conduct

By participating, you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Setup

```bash
git clone https://github.com/arkanzasfeziii/BlackForge.git
cd BlackForge
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Workflow

1. Fork and create a branch: `git checkout -b feat/your-feature`
2. Make changes following PEP 8 and existing code style
3. Add type hints and keep functions under ~50 lines
4. Run checks:
   ```bash
   make lint
   make test
   ```
5. Commit with [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat(jenkins): add pipeline script extraction
   fix(gitlab): handle pagination in project listing
   test(secrets): add edge case for base64 encoded keys
   ```
6. Open a Pull Request

## Adding a New Module

1. Create `blackforge/modules/your_platform.py`
2. Extend `BaseModule` from `blackforge/modules/base.py`
3. Implement the `run()` method
4. Register in `blackforge/cli.py` under `MODULE_REGISTRY`
5. Add tests in `tests/test_your_platform.py`
6. Update `blackforge/modules/__init__.py`

## Legal

All contributions must comply with the ethical use policy. BlackForge is
for authorized security testing only. Do not submit code intended for
unauthorized access.
