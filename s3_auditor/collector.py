"""
collector.py — talk to AWS and gather each bucket's security settings.

This is the ONLY file that calls AWS. It turns API responses into plain
Python objects (AccountConfig, BucketConfig). The rules in checks.py then
work on those objects, so the rules can be tested without AWS at all.

Every call here is read-only (Get*/List*). The auditor never changes anything
in your account.
"""

import json
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

# The four Block Public Access switches. All four on = fully blocked.
BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

# Error codes that just mean "this setting was never configured". That's a
# normal answer, not a failure. Anything else (AccessDenied, throttling...)
# means we couldn't check, which the report shows separately.
_NOT_CONFIGURED = {
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy",
    "ServerSideEncryptionConfigurationNotFoundError",
    "OwnershipControlsNotFoundError",
}


@dataclass
class AccountConfig:
    """Account-wide settings that affect every bucket."""

    account_id: str
    public_access_block: dict | None = None  # the 4 BPA flags; None = never configured
    errors: dict[str, str] = field(default_factory=dict)  # check name -> AWS error code


@dataclass
class BucketConfig:
    """One bucket's security-relevant settings."""

    name: str
    region: str
    public_access_block: dict | None = None  # the 4 BPA flags; None = never configured
    policy: dict | None = None               # parsed bucket policy JSON; None = no policy
    acl_grants: list = field(default_factory=list)
    encryption: str | None = None            # "AES256" (SSE-S3), "aws:kms", ... or None
    versioning: str = "Disabled"             # "Enabled", "Suspended", or "Disabled"
    logging_enabled: bool = False
    object_ownership: str | None = None      # "BucketOwnerEnforced" means ACLs are switched off
    errors: dict[str, str] = field(default_factory=dict)  # check name -> AWS error code


def _call(errors: dict, check: str, fn, **kwargs):
    """
    Run one AWS call. Returns the response, or None if the setting isn't
    configured. If AWS refuses (e.g. AccessDenied), the error code is recorded
    in errors[check] and None is returned, so one blocked check doesn't stop
    the whole audit.
    """
    try:
        return fn(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in _NOT_CONFIGURED:
            errors[check] = code
        return None


def collect_account(session, region: str) -> AccountConfig:
    """Read the account ID and the account-level Block Public Access settings."""
    account_id = session.client("sts", region_name=region).get_caller_identity()["Account"]
    account = AccountConfig(account_id=account_id)
    resp = _call(
        account.errors, "public_access_block",
        session.client("s3control", region_name=region).get_public_access_block,
        AccountId=account_id,
    )
    if resp:
        account.public_access_block = resp["PublicAccessBlockConfiguration"]
    return account


def list_bucket_names(session, region: str) -> list[str]:
    return [b["Name"] for b in session.client("s3", region_name=region).list_buckets()["Buckets"]]


def _bucket_region(s3, name: str, default: str) -> str:
    """Which region a bucket lives in. AWS reports us-east-1 as None, and old eu-west-1 buckets as 'EU'."""
    try:
        location = s3.get_bucket_location(Bucket=name)["LocationConstraint"]
    except ClientError:
        return default
    return {None: "us-east-1", "EU": "eu-west-1"}.get(location, location)


def collect_buckets(session, names: list[str], region: str) -> list[BucketConfig]:
    """Collect every named bucket, talking to each one in its own region."""
    home = session.client("s3", region_name=region)
    clients = {}
    buckets = []
    for name in names:
        bucket_region = _bucket_region(home, name, region)
        if bucket_region not in clients:
            clients[bucket_region] = session.client("s3", region_name=bucket_region)
        buckets.append(collect_bucket(clients[bucket_region], name, bucket_region))
    return buckets


def collect_bucket(s3, name: str, region: str) -> BucketConfig:
    """Read one bucket's settings, one API call per setting."""
    bucket = BucketConfig(name=name, region=region)
    errors = bucket.errors

    resp = _call(errors, "public_access_block", s3.get_public_access_block, Bucket=name)
    if resp:
        bucket.public_access_block = resp["PublicAccessBlockConfiguration"]

    resp = _call(errors, "policy", s3.get_bucket_policy, Bucket=name)
    if resp:
        bucket.policy = json.loads(resp["Policy"])

    resp = _call(errors, "acl", s3.get_bucket_acl, Bucket=name)
    if resp:
        bucket.acl_grants = resp["Grants"]

    resp = _call(errors, "encryption", s3.get_bucket_encryption, Bucket=name)
    if resp:
        rules = resp["ServerSideEncryptionConfiguration"]["Rules"]
        bucket.encryption = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")

    resp = _call(errors, "versioning", s3.get_bucket_versioning, Bucket=name)
    if resp:
        bucket.versioning = resp.get("Status", "Disabled")

    resp = _call(errors, "logging", s3.get_bucket_logging, Bucket=name)
    if resp:
        bucket.logging_enabled = "LoggingEnabled" in resp

    resp = _call(errors, "object_ownership", s3.get_bucket_ownership_controls, Bucket=name)
    if resp:
        bucket.object_ownership = resp["OwnershipControls"]["Rules"][0]["ObjectOwnership"]

    return bucket
