"""Tests for CLI argument parsing."""

from blackforge.cli import build_parser


def test_default_module():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.modules == ["github"]


def test_multiple_modules():
    parser = build_parser()
    args = parser.parse_args(["--modules", "github", "jenkins"])
    assert args.modules == ["github", "jenkins"]


def test_all_modules():
    parser = build_parser()
    args = parser.parse_args(["--modules", "all"])
    assert args.modules == ["all"]


def test_github_args():
    parser = build_parser()
    args = parser.parse_args(["--github-token", "ghp_test", "--github-org", "myorg"])
    assert args.github_token == "ghp_test"
    assert args.github_org == "myorg"


def test_delay_default():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.delay == 0.5


def test_output_flag():
    parser = build_parser()
    args = parser.parse_args(["-o", "results.json"])
    assert args.output == "results.json"
