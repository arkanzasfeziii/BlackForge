"""Command-line interface for BlackForge."""

from __future__ import annotations

import argparse
import textwrap

from blackforge.config import COMMAND, DEFAULT_DELAY, TOOL_NAME, VERSION
from blackforge.logger import log
from blackforge.models import EngagementContext, HAS_REQUESTS
from blackforge.modules import (
    ArgoCDModule,
    ArtifactModule,
    GitHubModule,
    GitLabModule,
    JenkinsModule,
)
from blackforge.output import dump_results, print_banner, print_legal


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
        examples:
          {COMMAND} --modules github --github-token ghp_xxx --github-org myorg --github-repo myorg/repo
          {COMMAND} --modules jenkins --jenkins-url http://jenkins:8080
          {COMMAND} --modules gitlab --gitlab-url https://gitlab.corp.com --gitlab-token glpat-xxx
          {COMMAND} --modules argocd --argocd-url https://argocd.corp.com
          {COMMAND} --modules artifact --artifact-url http://nexus:8081
          {COMMAND} --modules all --github-token TOKEN --jenkins-url URL --output loot.json
        """),
    )
    p.add_argument("--modules", nargs="+",
                   choices=["github", "jenkins", "gitlab", "argocd", "artifact", "all"],
                   default=["github"])
    p.add_argument("--github-token", default="")
    p.add_argument("--github-org", default="")
    p.add_argument("--github-repo", default="")
    p.add_argument("--jenkins-url", default="")
    p.add_argument("--jenkins-cmd", default="id")
    p.add_argument("--gitlab-url", default="")
    p.add_argument("--gitlab-token", default="")
    p.add_argument("--argocd-url", default="")
    p.add_argument("--artifact-url", default="")
    p.add_argument("-u", "--username", default="")
    p.add_argument("-p", "--password", default="")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    p.add_argument("--output", "-o", help="Save results to JSON file")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


MODULE_REGISTRY = {
    "github": (GitHubModule, lambda a: {"token": a.github_token, "org": a.github_org, "repo": a.github_repo}),
    "jenkins": (JenkinsModule, lambda a: {"url": a.jenkins_url, "username": a.username, "password": a.password}),
    "gitlab": (GitLabModule, lambda a: {"url": a.gitlab_url, "token": a.gitlab_token, "username": a.username, "password": a.password}),
    "argocd": (ArgoCDModule, lambda a: {"url": a.argocd_url, "username": a.username, "password": a.password}),
    "artifact": (ArtifactModule, lambda a: {"url": a.artifact_url, "username": a.username, "password": a.password}),
}

REQUIRES_URL = {"jenkins": "jenkins_url", "gitlab": "gitlab_url", "argocd": "argocd_url", "artifact": "artifact_url"}


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    print_banner()
    if not print_legal(args.yes):
        return 1
    if not HAS_REQUESTS:
        print("ERROR: pip install requests")
        return 2

    ctx = EngagementContext(delay=args.delay)
    modules_to_run = list(MODULE_REGISTRY.keys()) if "all" in args.modules else args.modules

    for mod_name in modules_to_run:
        url_attr = REQUIRES_URL.get(mod_name)
        if url_attr and not getattr(args, url_attr, ""):
            log(f"--{url_attr.replace('_', '-')} required for {mod_name}", "WARN")
            continue

        mod_cls, kwargs_fn = MODULE_REGISTRY[mod_name]
        log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            mod = mod_cls()
            results = mod.run(ctx, **kwargs_fn(args))
            ctx.results.extend(results)
        except Exception as exc:
            log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0
