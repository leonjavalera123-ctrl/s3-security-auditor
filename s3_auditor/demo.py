"""
demo.py — a simulated AWS account to audit, so the tool can be tried without
an AWS account.

It uses moto, a library that fakes AWS inside this Python process. Every
boto3 call is answered locally. Nothing is sent to Amazon, and the fake
credentials below couldn't work there anyway.

The story: "Acme" turned on protections bucket by bucket, but missed some.
  acme-prod-backups    fully hardened, should produce no findings
  acme-access-logs     receives the access logs; decent but unversioned
  acme-website-assets  someone made it public with a bucket policy
  acme-legacy-uploads  an old bucket made public with an ACL
  acme-data-lake       has a public policy that Block Public Access is
                       overriding: safe today, one click from exposed
"""

import json
from contextlib import contextmanager

import boto3
from moto import mock_aws

REGION = "us-east-1"
ALL_ON = {flag: True for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def _deny_http(bucket: str, principal="*") -> dict:
    """The standard 'reject anything not sent over HTTPS' statement."""
    return {
        "Sid": "DenyInsecureTransport",
        "Effect": "Deny",
        "Principal": principal,
        "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }


def _public_read(bucket: str) -> dict:
    return {
        "Sid": "PublicRead",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{bucket}/*",
    }


def _policy(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _create(s3, name: str, region: str, ownership: str = "BucketOwnerEnforced", sse: str = "AES256"):
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_ownership_controls(
        Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": ownership}]}
    )
    s3.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": sse}}]},
    )


def build_demo_account(session) -> None:
    """Create the Acme buckets inside the (already mocked) AWS session."""
    s3 = session.client("s3", region_name=REGION)
    eu = session.client("s3", region_name="eu-west-1")

    logs = "acme-access-logs"
    _create(s3, logs, REGION)
    s3.put_public_access_block(Bucket=logs, PublicAccessBlockConfiguration=ALL_ON)
    # {"AWS": "*"} means the same as "*" to AWS. moto's logging-permission
    # check crashes on the short "*" form, so the log bucket uses the long one.
    s3.put_bucket_policy(Bucket=logs, Policy=_policy(_deny_http(logs, principal={"AWS": "*"}), {
        "Sid": "S3ServerAccessLogs",
        "Effect": "Allow",
        "Principal": {"Service": "logging.s3.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": f"arn:aws:s3:::{logs}/*",
    }))

    backups = "acme-prod-backups"
    _create(s3, backups, REGION, sse="aws:kms")
    s3.put_public_access_block(Bucket=backups, PublicAccessBlockConfiguration=ALL_ON)
    s3.put_bucket_policy(Bucket=backups, Policy=_policy(_deny_http(backups)))
    s3.put_bucket_versioning(Bucket=backups, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_logging(Bucket=backups, BucketLoggingStatus={
        "LoggingEnabled": {"TargetBucket": logs, "TargetPrefix": f"{backups}/"}
    })

    website = "acme-website-assets"
    _create(s3, website, REGION)
    s3.put_bucket_policy(Bucket=website, Policy=_policy(_public_read(website)))

    legacy = "acme-legacy-uploads"
    _create(s3, legacy, REGION, ownership="ObjectWriter")
    s3.put_bucket_acl(Bucket=legacy, ACL="public-read")

    # The public policy went on first; Block Public Access was switched on later.
    lake = "acme-data-lake"
    _create(eu, lake, "eu-west-1", sse="aws:kms")
    eu.put_bucket_policy(Bucket=lake, Policy=_policy(_deny_http(lake), _public_read(lake)))
    eu.put_public_access_block(Bucket=lake, PublicAccessBlockConfiguration=ALL_ON)
    eu.put_bucket_versioning(Bucket=lake, VersioningConfiguration={"Status": "Enabled"})


@contextmanager
def demo_session():
    """Yield a boto3 session wired to the simulated Acme account."""
    with mock_aws():
        session = boto3.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name=REGION,
        )
        build_demo_account(session)
        yield session
