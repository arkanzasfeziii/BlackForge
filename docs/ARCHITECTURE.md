# Architecture

## Package Structure

```
blackforge/
├── cli.py               # Argument parsing, module dispatch
├── config.py            # Tool metadata, constants
├── models.py            # AttackResult, Credential, EngagementContext
├── logger.py            # Colored terminal logging
├── output.py            # Banner, legal warning, result formatting
├── exceptions.py        # Typed exception hierarchy
│
├── modules/             # One file per CI/CD platform
│   ├── base.py          # BaseModule ABC — all modules extend this
│   ├── github.py        # GitHub Actions exploitation
│   ├── jenkins.py       # Jenkins RCE & credential dump
│   ├── gitlab.py        # GitLab CI variable & runner theft
│   ├── argocd.py        # ArgoCD default cred & app takeover
│   └── artifact.py      # Nexus/Artifactory/Harbor attacks
│
├── utils/               # Shared utilities
│   ├── http.py          # Rate-limited HTTP request wrapper
│   └── secrets.py       # Regex-based secret pattern scanner
│
└── data/                # Static data (no logic)
    ├── payloads.py      # Groovy scripts, workflow PoCs
    ├── credentials.py   # Default credential lists
    └── endpoints.py     # API paths per platform
```

## Data Flow

```
CLI (argparse)
    │
    ▼
EngagementContext ──────────────────────────┐
    │                                       │
    ▼                                       │
Module.run(ctx, **kwargs)                   │
    │                                       │
    ├── utils/http.request()                │
    ├── utils/secrets.scan_secrets()        │
    │                                       │
    ├── ctx.results.append(AttackResult)    │
    ├── ctx.credentials.append(Credential)  │
    └── ctx.loot[key] = data                │
                                            │
    ┌───────────────────────────────────────┘
    ▼
output.dump_results(ctx)
    │
    ├── Terminal: colored summary
    └── JSON file: structured report
```

## Key Design Decisions

**EngagementContext as shared state**: All modules read from and write to
the same context object. Credential found by Jenkins can be reused by
another module in the same run.

**BaseModule ABC**: Every attack module implements `run(ctx, **kwargs)`.
Adding a new platform means creating one file and registering it in
`MODULE_REGISTRY` — no existing code changes required (Open/Closed Principle).

**Separated data layer**: Groovy payloads, default credentials, and API
paths live in `data/` with no business logic. Easy to update without
touching module code.

**HTTP wrapper**: All network calls go through `utils/http.request()` which
handles rate limiting (configurable delay), SSL verification skip, and
timeout. Modules never call `requests` directly.

## Adding a New Module

1. Create `blackforge/modules/your_platform.py`
2. Define a class extending `BaseModule`
3. Implement `run(self, ctx, **kwargs) -> List[AttackResult]`
4. Add platform-specific data to `blackforge/data/`
5. Register in `cli.py: MODULE_REGISTRY`
6. Add to `modules/__init__.py`
