"""API endpoint paths for each supported platform."""

from __future__ import annotations

from typing import Dict, List

JENKINS_PATHS: Dict[str, str] = {
    "who_am_i": "/whoAmI/api/json",
    "credentials": "/credentials/store/system/domain/_/api/json?depth=2",
    "jobs": "/api/json?tree=jobs[name,url,buildable,builds[number,result]]",
    "script": "/scriptText",
    "crumb": "/crumbIssuer/api/json",
    "build_queue": "/queue/api/json",
    "users": "/asynchPeople/api/json",
    "nodes": "/computer/api/json",
}

GITLAB_PATHS: Dict[str, str] = {
    "projects": "/api/v4/projects?membership=true&per_page=100",
    "groups": "/api/v4/groups?per_page=100",
    "users": "/api/v4/users?per_page=100",
    "runners": "/api/v4/runners/all",
    "vars": "/api/v4/projects/{id}/variables",
    "ci_vars": "/api/v4/groups/{id}/variables",
    "pipeline": "/api/v4/projects/{id}/pipelines",
    "jobs": "/api/v4/projects/{id}/jobs",
}

ARGOCD_PATHS: Dict[str, str] = {
    "info": "/api/v1/version",
    "apps": "/api/v1/applications",
    "clusters": "/api/v1/clusters",
    "repos": "/api/v1/repositories",
    "settings": "/api/v1/settings",
}

ARTIFACT_PATHS: Dict[str, List[str]] = {
    "nexus": [
        "/service/rest/v1/repositories",
        "/service/rest/v1/assets?repository=maven-central",
        "/service/rest/v1/security/users",
        "/#browse/browse:browse",
    ],
    "artifactory": [
        "/api/system/info",
        "/api/repositories",
        "/api/security/users",
        "/ui/",
    ],
    "harbor": [
        "/api/v2.0/systeminfo",
        "/api/v2.0/projects",
        "/api/v2.0/users",
        "/",
    ],
}
