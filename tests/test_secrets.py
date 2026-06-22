"""Tests for secret pattern scanner."""

from blackforge.utils.secrets import scan_secrets


def test_detect_aws_key():
    text = 'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"'
    results = scan_secrets(text)
    assert any(r["type"] == "AWS_ACCESS_KEY" for r in results)


def test_detect_github_pat():
    text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    results = scan_secrets(text)
    assert any(r["type"] == "GITHUB_PAT" for r in results)


def test_detect_gitlab_pat():
    text = "PRIVATE_TOKEN=glpat-abcdefghijklmnopqrst"
    results = scan_secrets(text)
    assert any(r["type"] == "GITLAB_PAT" for r in results)


def test_detect_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
    results = scan_secrets(text)
    assert any(r["type"] == "PRIVATE_KEY" for r in results)


def test_detect_password():
    text = 'password = "SuperSecret123!"'
    results = scan_secrets(text)
    assert any(r["type"] == "PASSWORD" for r in results)


def test_no_false_positive_on_clean_text():
    text = "This is a normal log line with no secrets."
    results = scan_secrets(text)
    assert results == []


def test_truncates_long_values():
    text = 'password = "' + "A" * 300 + '"'
    results = scan_secrets(text)
    for r in results:
        assert len(r["value"]) <= 200
