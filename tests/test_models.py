"""Tests for data models."""

from blackforge.models import AttackResult, Credential, EngagementContext


def test_attack_result_defaults():
    r = AttackResult(module="github", action="scan", status="SUCCESS")
    assert r.module == "github"
    assert r.severity == "INFO"
    assert r.target == ""


def test_credential_creation():
    c = Credential(
        type="AWS_ACCESS_KEY",
        value={"key": "AKIAIOSFODNN7EXAMPLE"},
        source="jenkins:env",
    )
    assert c.type == "AWS_ACCESS_KEY"
    assert c.notes == ""


def test_engagement_context_defaults():
    ctx = EngagementContext()
    assert ctx.results == []
    assert ctx.credentials == []
    assert ctx.loot == {}
    assert ctx.delay == 0.5


def test_engagement_context_custom_delay():
    ctx = EngagementContext(delay=2.0)
    assert ctx.delay == 2.0
