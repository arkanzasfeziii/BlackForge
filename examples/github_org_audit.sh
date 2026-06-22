#!/bin/bash
# Audit a GitHub organization for CI/CD security issues
#
# Prerequisites:
#   - GitHub PAT with repo, admin:org, workflow scopes
#   - pip install -r requirements.txt
#
# What this does:
#   1. Validates token and shows scopes
#   2. Enumerates all repos in the org
#   3. Lists org-level and repo-level secret names
#   4. Downloads all workflow YAML files and scans for injection vectors
#   5. Scans last 5 Actions run logs for leaked credentials
#
# Expected output:
#   - Workflow injection findings (github.event interpolation in run: steps)
#   - Secret names at org and repo level
#   - Any credentials accidentally printed in workflow logs

python -m blackforge \
  --modules github \
  --github-token "$GITHUB_TOKEN" \
  --github-org "$1" \
  --github-repo "$1/$2" \
  --output "github_audit_$(date +%Y%m%d).json" \
  -y
