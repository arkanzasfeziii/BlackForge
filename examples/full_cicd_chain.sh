#!/bin/bash
# Full CI/CD supply chain assessment across all platforms
#
# Prerequisites:
#   - Tokens/URLs for each platform in scope
#   - pip install -r requirements.txt
#
# What this does:
#   Runs all five modules in sequence:
#   GitHub → Jenkins → GitLab → ArgoCD → Artifact Registry
#
# Findings from each module accumulate in the engagement context,
# so credentials found in Jenkins can inform later module checks.

python -m blackforge \
  --modules all \
  --github-token "$GITHUB_TOKEN" \
  --github-org "$GITHUB_ORG" \
  --jenkins-url "$JENKINS_URL" \
  --gitlab-url "$GITLAB_URL" \
  --gitlab-token "$GITLAB_TOKEN" \
  --argocd-url "$ARGOCD_URL" \
  --artifact-url "$ARTIFACT_URL" \
  --delay 1.0 \
  --output "full_engagement_$(date +%Y%m%d).json" \
  -y

echo ""
echo "Results saved. Review the JSON report for findings."
