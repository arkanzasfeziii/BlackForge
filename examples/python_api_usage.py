"""Example: Using BlackForge modules programmatically from Python.

This shows how to import and run individual modules without the CLI,
useful for integrating BlackForge into larger automation pipelines.
"""

from blackforge.models import EngagementContext
from blackforge.modules.github import GitHubModule
from blackforge.modules.jenkins import JenkinsModule


def github_audit(token: str, org: str) -> None:
    ctx = EngagementContext(delay=0.3)
    module = GitHubModule()
    results = module.run(ctx, token=token, org=org)

    for r in results:
        print(f"[{r.severity}] {r.module}/{r.action}: {r.notes}")

    print(f"\nCredentials found: {len(ctx.credentials)}")
    for cred in ctx.credentials:
        print(f"  [{cred.type}] {cred.source}")


def jenkins_check(url: str) -> None:
    ctx = EngagementContext(delay=0.5)
    module = JenkinsModule()
    results = module.run(ctx, url=url)

    critical = [r for r in results if r.severity == "CRITICAL"]
    print(f"\nJenkins: {len(critical)} critical findings")
    for r in critical:
        print(f"  {r.action}: {r.notes}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python python_api_usage.py github TOKEN ORG")
        print("  python python_api_usage.py jenkins URL")
        sys.exit(1)

    if sys.argv[1] == "github":
        github_audit(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "jenkins":
        jenkins_check(sys.argv[2])
