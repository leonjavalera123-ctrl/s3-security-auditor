"""
End-to-end tests: run the tool the way a user would and check the exit code
and the report.
"""

import json

import pytest

from s3_auditor.cli import main


@pytest.fixture
def no_aws_config(monkeypatch, tmp_path):
    """
    Make sure these tests can't see real AWS credentials or config on the
    machine running them, and don't wait on the EC2 metadata service.
    """
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


def test_demo_text_report(capsys):
    assert main(["--demo"]) == 1
    out = capsys.readouterr().out
    assert "Buckets checked   5" in out
    assert "Findings          16  (2 high, 5 medium, 9 low)" in out
    assert "[HIGH] PUBLIC_POLICY  acme-website-assets" in out
    assert "[HIGH] PUBLIC_ACL  acme-legacy-uploads" in out


def test_demo_json_report(capsys):
    main(["--demo", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["account"]["account_id"] == "123456789012"
    assert len(report["buckets"]) == 5
    hardened = [f for f in report["findings"] if f["resource"] == "acme-prod-backups"]
    assert hardened == []


def test_single_bucket_filter(capsys):
    main(["--demo", "--bucket", "acme-data-lake"])
    out = capsys.readouterr().out
    assert "Buckets checked   1" in out
    assert "acme-website-assets" not in out


def test_unknown_bucket_is_an_error(capsys):
    assert main(["--demo", "--bucket", "not-a-bucket"]) == 2
    assert "bucket not found" in capsys.readouterr().err


def test_output_file(tmp_path, capsys):
    out_file = tmp_path / "audit.json"
    main(["--demo", "--format", "json", "-o", str(out_file)])
    assert "Report written to" in capsys.readouterr().out
    assert len(json.loads(out_file.read_text(encoding="utf-8"))["findings"]) == 16


def test_no_credentials_gives_clear_error(no_aws_config, capsys):
    assert main([]) == 2
    err = capsys.readouterr().err
    assert "no AWS credentials found" in err
    assert "Traceback" not in err


def test_unknown_profile_gives_clear_error(no_aws_config, capsys):
    assert main(["--profile", "nope"]) == 2
    assert "profile 'nope' not found" in capsys.readouterr().err
