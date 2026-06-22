# Usage Guide

## Basic Syntax

```bash
blackforge --modules <module> [module options] [--output report.json]
```

## Modules

| Module | Target | Required Flag |
|--------|--------|---------------|
| `github` | GitHub Actions & repos | `--github-token` |
| `jenkins` | Jenkins CI server | `--jenkins-url` |
| `gitlab` | GitLab CI/CD | `--gitlab-url` + `--gitlab-token` |
| `argocd` | ArgoCD deployments | `--argocd-url` |
| `artifact` | Nexus/Artifactory/Harbor | `--artifact-url` |
| `all` | Everything above | All flags combined |

## GitHub

Enumerate org, scan workflows for injection vectors, search logs for leaked secrets:

```bash
blackforge --modules github \
  --github-token ghp_your_token \
  --github-org target-org \
  --github-repo target-org/app \
  -y
```

## Jenkins

Check for anonymous access, attempt Groovy RCE, dump credentials:

```bash
blackforge --modules jenkins \
  --jenkins-url http://jenkins.target.com:8080 \
  -y
```

With credentials:

```bash
blackforge --modules jenkins \
  --jenkins-url http://jenkins.target.com:8080 \
  -u admin -p admin \
  -y
```

## GitLab

Dump CI/CD variables, steal runner tokens, scan pipeline logs:

```bash
blackforge --modules gitlab \
  --gitlab-url https://gitlab.target.com \
  --gitlab-token glpat-your_token \
  -y
```

## ArgoCD

Detect version, brute-force default credentials, enumerate apps/clusters:

```bash
blackforge --modules argocd \
  --argocd-url https://argocd.target.com \
  -y
```

## Artifact Registry

Detect platform (Nexus/Artifactory/Harbor), check anonymous access,
test default credentials, find dependency confusion vectors:

```bash
blackforge --modules artifact \
  --artifact-url http://nexus.target.com:8081 \
  -y
```

## Full Chain

Run all modules in sequence:

```bash
blackforge --modules all \
  --github-token ghp_xxx --github-org corp \
  --jenkins-url http://jenkins:8080 \
  --gitlab-url https://gitlab.corp.com --gitlab-token glpat-xxx \
  --argocd-url https://argocd.corp.com \
  --artifact-url http://nexus:8081 \
  --output engagement.json \
  -y
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--delay` | `0.5` | Seconds between requests |
| `--output` / `-o` | — | Save JSON report |
| `--yes` / `-y` | — | Skip legal warning |
| `-u` / `--username` | — | Auth username |
| `-p` / `--password` | — | Auth password |
