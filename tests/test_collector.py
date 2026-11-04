"""
Tests for collector.py, run against moto's simulated AWS. Nothing here
touches a real account.
"""

import pytest
from botocore.exceptions import ClientError

from s3_auditor.collector import _call, collect_account, collect_buckets, list_bucket_names
from s3_auditor.demo import demo_session


@pytest.fixture(scope="module")
def collected():
    with demo_session() as session:
        account = collect_account(session, "us-east-1")
        names = list_bucket_names(session, "us-east-1")
        buckets = {b.name: b for b in collect_buckets(session, names, "us-east-1")}
    return account, buckets


def test_account(collected):
    account, _ = collected
    assert account.account_id == "123456789012"
    assert account.public_access_block is None  # never configured in the demo
    assert account.errors == {}


def test_all_buckets_found(collected):
    _, buckets = collected
    assert set(buckets) == {
        "acme-access-logs", "acme-prod-backups", "acme-website-assets",
        "acme-legacy-uploads", "acme-data-lake",
    }


def test_hardened_bucket_settings(collected):
    b = collected[1]["acme-prod-backups"]
    assert b.region == "us-east-1"
    assert all(b.public_access_block.values())
    assert b.encryption == "aws:kms"
    assert b.versioning == "Enabled"
    assert b.logging_enabled is True
    assert b.object_ownership == "BucketOwnerEnforced"
    assert b.policy["Statement"][0]["Sid"] == "DenyInsecureTransport"
    assert b.errors == {}


def test_bucket_in_another_region(collected):
    assert collected[1]["acme-data-lake"].region == "eu-west-1"


def test_unconfigured_settings_are_none_not_errors(collected):
    b = collected[1]["acme-legacy-uploads"]
    assert b.public_access_block is None
    assert b.policy is None
    assert b.versioning == "Disabled"
    assert b.errors == {}


def test_acl_grants_collected(collected):
    uris = [g["Grantee"].get("URI") for g in collected[1]["acme-legacy-uploads"].acl_grants]
    assert "http://acs.amazonaws.com/groups/global/AllUsers" in uris


def _raise(code):
    def fn(**kwargs):
        raise ClientError({"Error": {"Code": code, "Message": "test"}}, "TestOperation")
    return fn


def test_call_records_access_denied():
    errors = {}
    assert _call(errors, "policy", _raise("AccessDenied"), Bucket="b") is None
    assert errors == {"policy": "AccessDenied"}


def test_call_treats_not_configured_as_normal():
    errors = {}
    assert _call(errors, "policy", _raise("NoSuchBucketPolicy"), Bucket="b") is None
    assert errors == {}
