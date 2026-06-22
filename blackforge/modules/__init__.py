"""Attack modules for CI/CD platforms and artifact registries."""

from blackforge.modules.github import GitHubModule
from blackforge.modules.jenkins import JenkinsModule
from blackforge.modules.gitlab import GitLabModule
from blackforge.modules.argocd import ArgoCDModule
from blackforge.modules.artifact import ArtifactModule

__all__ = [
    "GitHubModule",
    "JenkinsModule",
    "GitLabModule",
    "ArgoCDModule",
    "ArtifactModule",
]
