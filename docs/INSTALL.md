# Installation

## Requirements

- Python 3.10+
- `requests` library

## Quick Install

```bash
git clone https://github.com/arkanzasfeziii/BlackForge.git
cd BlackForge
pip install -r requirements.txt
```

## Install as Package

```bash
pip install .
blackforge --version
```

## Development Install

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
make test
```

## Docker

```bash
docker build -t blackforge .
docker run --rm blackforge --modules github --github-token YOUR_TOKEN
```

## Verify Installation

```bash
python -m blackforge --version
```
