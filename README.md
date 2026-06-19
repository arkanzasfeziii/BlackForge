# BlackForge — CI/CD & Supply Chain Attack Framework

> **Test every link in the software delivery chain — from workflow injection in GitHub Actions to Groovy RCE in Jenkins to unmasked secrets in GitLab CI variables.**

---

## Threat Model

Modern software delivery pipelines are trusted by design. CI/CD systems execute arbitrary code on every commit, hold credentials to production environments, and are rarely included in the attack surface a security team monitors. That trust is the vulnerability.

BlackForge models the attacker who enters through the pipeline — not the application:

| Stage | What Fails | Adversary Action |
|---|---|---|
| **GitHub Actions** | Workflow files interpolate `github.event.head_commit.message` directly into `run:` steps | Inject shell commands via PR title or commit message — no merge required |
| **GitHub Actions** | Organization secrets scoped too broadly across repositories | Enumerate all org repos, extract secret names, generate exfiltration PoC workflow |
| **Jenkins** | Script Console left accessible or exposed without authentication | Execute Groovy payload: dump credentials, enumerate nodes, extract environment variables |
| **Jenkins** | Built-in credential store accessed via Credentials REST API without role scoping | Retrieve plaintext credentials for AWS, GCP, SSH keys, API tokens |
| **GitLab CI** | CI/CD variables marked as "protected" but not "masked" | Extract variables from pipeline logs; dump unmasked secrets via API for any accessible project |
| **GitLab** | Runner registration tokens exposed in project settings | Register a malicious runner — intercept future pipeline jobs |
| **ArgoCD** | Default admin credentials not rotated after deployment | Access all managed clusters, applications, and connected repositories |
| **Artifact Registries** | Nexus/Artifactory/Harbor deployed with default credentials, anonymous access enabled | Pull internal packages, identify internal namespace conventions for dependency confusion |
| **Dependency Confusion** | Internal packages share names with public registry packages without scope protection | Identify internal package names — upstream for confusion attack payload delivery |

**Scope:** Authorized red team engagements simulating supply chain compromise vectors and CI/CD pipeline attack paths.

---

## Why This Exists

The supply chain is the new perimeter. Attackers don't need to compromise an application — they compromise the pipeline that builds and deploys it.

After SolarWinds, the industry acknowledged that build systems are high-value targets. Most organizations responded by adding more secrets to their pipelines without asking whether those pipelines were hardened to hold them.

BlackForge answers:
- Does your Jenkins Script Console require authentication?
- Do your GitHub Actions workflows interpolate untrusted input into shell commands?
- Can an attacker with a read token extract unmasked CI/CD variables from GitLab?
- Are your artifact registries accepting anonymous pulls of internal packages?
- What happens when ArgoCD still uses `admin:password`?

The framework tests these questions systematically across the five platforms where delivery pipeline compromise is most impactful.

---

## Capabilities

### GitHub Attack Module
- **Token validation:** Verify scope and permissions of discovered GitHub PATs
- **Organization enumeration:** List all repositories, members, and team structures under an org
- **Secret enumeration:** List secret names defined at org and repo level (values masked by GitHub — names expose what exists)
- **Workflow injection detection:** Download all workflow YAML files; scan for dangerous interpolation patterns — `github.event.head_commit.message`, `github.head_ref`, PR title in `run:` blocks
- **Actions run log scanning:** Parse historical workflow logs for accidentally printed secrets matching `SECRET_PATTERNS`
- **PoC workflow generator:** Produce a ready-to-inject workflow that exfiltrates `secrets.*` to an external endpoint — demonstrates exploitability without requiring a real commit

### Jenkins Attack Module
- **Anonymous access detection:** Check `/api/json` for unauthenticated access
- **Groovy RCE via Script Console:** Execute arbitrary Groovy on the Jenkins controller — `whoami`, `hostname`, full environment dump
- **Credential extraction:** Groovy payload that iterates the credential store and extracts ID, type, username, password, secret, API token, and private key source for every stored credential
- **Credentials REST API fallback:** Attempt credential listing via `/credentials/store/system/domain/_/api/json` with and without authentication
- **Job and node enumeration:** List all build jobs and connected build agents

### GitLab Attack Module
- **Token validation and admin detection:** Verify token scope; detect admin-level access
- **Project enumeration:** List all accessible projects with visibility and permission level
- **CI/CD variable extraction:** Dump all project-level CI/CD variables — flags unmasked variables that appear in logs
- **Runner token theft:** Extract runner registration tokens from project settings — enables rogue runner registration
- **Pipeline log scanning:** Search historical pipeline job logs for secrets matching `SECRET_PATTERNS`

### ArgoCD Attack Module
- **Version fingerprinting:** Detect ArgoCD deployment via `/api/version`
- **Default credential brute-force:** Test `admin:admin`, `admin:password`, and common defaults
- **Post-auth enumeration:** List managed applications, connected clusters, and registered repositories after successful authentication

### Artifact Registry Module
- **Platform detection:** Identify Nexus Repository Manager, JFrog Artifactory, or Harbor from response headers and UI fingerprints
- **Anonymous access check:** Test whether package pull/browse works without credentials
- **Default credential testing:** Spray known defaults (`admin:admin123`, `admin:password`, `harbor:Harbor12345`)
- **Dependency confusion detection:** Enumerate internal package names and namespaces — surface candidates for confusion attack targeting

### Secret Pattern Detection

BlackForge scans workflow logs, pipeline outputs, and environment dumps for:

```
AWS_ACCESS_KEY_ID · Google API Key · GitHub PAT (ghp_) · GitLab PAT (glpat-)
OpenAI Key (sk-) · PASSWORD · API_KEY · SECRET · PRIVATE_KEY
CONNECTION_STRING · ACCESS_TOKEN · DATABASE_URL
```

---

## Architecture

```
Target (URL · token · platform)
            │
            ▼
    Platform Detection
  ┌──────────────────────────────┐
  │  GitHub · Jenkins · GitLab  │
  │  ArgoCD · Artifact Registry │
  └──────────────────────────────┘
            │
     ┌──────┼──────┐──────┐──────┐
     ▼      ▼      ▼      ▼      ▼
  GitHub  Jenkins GitLab ArgoCD Artifact
  Module  Module  Module Module Module
     │      │      │      │      │
     └──────┴──────┴──────┴──────┘
                    │
                    ▼
         SECRET_PATTERNS Scanner
                    │
                    ▼
            JSON Report
     (platform · action · finding · severity)
```

---

## Attack Flow

1. **Platform enumeration** — identify which CI/CD platforms are deployed at the target organization via URL patterns, response headers, and fingerprinting
2. **Authentication testing** — validate provided tokens/credentials; detect anonymous access paths; brute-force known defaults (Jenkins, ArgoCD, Artifactory)
3. **Workflow analysis (GitHub)** — pull all workflow YAML files from org repositories; parse `run:` blocks for dangerous interpolation of `github.event.*` values; flag injection vectors
4. **Credential extraction (Jenkins)** — if Script Console is accessible, execute Groovy payload to dump the full credential store — AWS keys, SSH private keys, API tokens, service account passwords
5. **Variable extraction (GitLab)** — dump CI/CD variables for all accessible projects; flag any unmasked variable that contains credential patterns
6. **PoC generation** — for each confirmed injection vector, generate a proof-of-concept workflow or Groovy payload demonstrating the actual impact (secret exfiltration, command execution)
7. **Dependency confusion surface** — enumerate internal package names from artifact registries; report namespaces lacking scope protection as confusion attack candidates
8. **Report** — structured JSON output per finding with platform, action taken, finding details, and severity classification

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# GitHub: enumerate org, scan workflows, check for injection vectors
python blackforge.py --platform github --token ghp_xxxx --org target-org

# GitHub: scan Actions run logs for exposed secrets
python blackforge.py --platform github --token ghp_xxxx --org target-org --modules logs

# Jenkins: test anonymous access + attempt Groovy RCE
python blackforge.py --platform jenkins --url https://jenkins.internal.corp

# Jenkins: authenticated credential dump via Groovy
python blackforge.py --platform jenkins --url https://jenkins.corp --username admin --password found-pass

# GitLab: dump unmasked CI/CD variables across all projects
python blackforge.py --platform gitlab --token glpat-xxxx --url https://gitlab.corp.com

# ArgoCD: default credential brute-force + post-auth enumeration
python blackforge.py --platform argocd --url https://argocd.k8s.corp

# Artifact registry: detect platform, test anonymous access, find confusion candidates
python blackforge.py --platform artifact --url https://nexus.corp.internal

# Full engagement — all platforms
python blackforge.py --modules all --output supply-chain-findings.json --yes
```

---

## Output

```
14:02:11 [INFO]  [GitHub] Token validated — scope: repo, admin:org, read:packages
14:02:12 [INFO]  [GitHub] Organization: target-corp | 47 repos | 83 members
14:02:13 [CRIT]  [GitHub/Workflows] Injection vector in .github/workflows/pr-check.yml:
                 run: echo "Building ${{ github.event.pull_request.title }}"
14:02:13 [CRIT]  [GitHub/Workflows] PoC generated → inject.yml (exfiltrates secrets.*)
14:02:14 [CRIT]  [GitHub/Logs] Secret leaked in run #482: AWS_ACCESS_KEY_ID=AKIA...

14:02:15 [CRIT]  [Jenkins] Anonymous access confirmed — /api/json readable
14:02:16 [CRIT]  [Jenkins/Groovy] RCE via Script Console — user: jenkins | host: build-01
14:02:17 [CRIT]  [Jenkins/Groovy] Credential dump — 12 entries extracted:
                 aws-prod-key [AWS] AKIAIOSFODNN7EXAMPLE
                 deploy-ssh   [SSH] -----BEGIN RSA PRIVATE KEY-----
                 gitlab-token [Secret] glpat-xxxxxxxxxxxx

14:02:18 [WARN]  [GitLab] 6 unmasked CI/CD variables across 3 projects
14:02:18 [CRIT]  [GitLab] Variable DB_PASSWORD (project: api-service) — unmasked, in logs
14:02:19 [CRIT]  [GitLab] Runner token found: GR1348941xxxxxxxx — rogue runner feasible

14:02:20 [CRIT]  [ArgoCD] Default credential accepted: admin:admin
14:02:21 [INFO]  [ArgoCD] 8 managed applications | 3 clusters | 11 repositories

[✓] Supply chain audit complete — 9 critical findings | report: supply-chain-findings.json
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Module |
|---|---|---|
| Supply Chain Compromise: CI/CD | T1195.002 | GitHubModule, JenkinsModule |
| Unsecured Credentials: CI/CD Variables | T1552.004 | GitLabModule, GitHubModule |
| Command and Scripting Interpreter: Groovy | T1059 | JenkinsModule |
| Valid Accounts: Cloud Accounts | T1078.004 | ArgoCDModule, ArtifactModule |
| Exploitation of Remote Services | T1210 | JenkinsModule (Script Console RCE) |
| Steal Application Access Token | T1528 | GitHubModule, GitLabModule |
| Account Discovery | T1087 | GitHubModule (org member enumeration) |

**Tactics:** TA0001 Initial Access · TA0006 Credential Access · TA0003 Persistence (rogue runner) · TA0002 Execution (Groovy RCE)

---

## CWE Coverage Exercised

| CWE | Description | Where |
|---|---|---|
| CWE-78 | OS Command Injection | GitHub Actions workflow injection |
| CWE-94 | Code Injection | Jenkins Groovy Script Console |
| CWE-312 | Cleartext Storage of Sensitive Information | GitLab unmasked CI/CD variables |
| CWE-522 | Insufficiently Protected Credentials | Jenkins credential store, pipeline logs |
| CWE-306 | Missing Authentication for Critical Function | Jenkins anonymous Script Console access |
| CWE-1103 | Use of Platform-Dependent Third Party Components | Dependency confusion candidates |

---

## Legal Notice

BlackForge is designed exclusively for authorized penetration testing and security assessment activities where explicit written permission has been obtained from the asset owner. Testing CI/CD systems and supply chain components of organizations you do not have explicit authorization to assess is illegal. The author assumes no liability for misuse.
