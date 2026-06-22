# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-22

### Changed
- Complete architectural rewrite from single-file script to modular package
- Each CI/CD platform is now an independent module under `blackforge/modules/`
- Abstract base class (`BaseModule`) enforces consistent module interface
- Custom exception hierarchy for typed error handling
- Separated concerns: config, models, logger, utils, data, CLI, output

### Added
- `blackforge/modules/base.py` — abstract base module
- `blackforge/utils/secrets.py` — standalone secret pattern scanner
- `blackforge/utils/http.py` — HTTP request wrapper
- `blackforge/data/` — payloads, credentials, and endpoint definitions
- `blackforge/exceptions.py` — custom exception classes
- Unit tests for models, secret scanner, and CLI
- `pyproject.toml` with full package metadata and tool configuration
- `Makefile` for development workflow
- `CHANGELOG.md`

## [1.0.0] - 2026-06-20

### Added
- Initial release: single-file framework covering GitHub Actions, Jenkins,
  GitLab CI, ArgoCD, and artifact registry attacks
