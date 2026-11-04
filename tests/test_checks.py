"""
Tests for checks.py. No AWS and no moto: the rules work on plain Python
objects, so each test builds exactly the settings it needs.
"""

from s3_auditor.checks import (
    ALL_USERS,
    AUTHENTICATED_USERS,
    check_account_bpa,
    check_acls_enabled,
    check_bucket_bpa,
    check_encryption,
    check_logging,
    check_public_acl,
    check_public_policy,
    check_tls,
    check_versioning,
    run_checks,
)
from s3_auditor.collector import BPA_FLAGS, AccountConfig, BucketConfig

ALL_ON = {flag: True for flag in BPA_FLAGS}
DENY_HTTP = {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::b/*",
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}
PUBLIC_READ = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}


def account(bpa=None) -> AccountConfig:
    return AccountConfig(account_id="123456789012", public_access_block=bpa)


def hardened(**overrides) -> BucketConfig:
    """A bucket that passes every check. Tests change one thing at a time."""
    settings = dict(
        name="b",
        region="us-east-1",
        public_access_block=dict(ALL_ON),
        policy={"Statement": [DENY_HTTP]},
        encryption="aws:kms",
        versioning="Enabled",
        logging_enabled=True,
        object_ownership="BucketOwnerEnforced",
    )
    settings.update(overrides)
    return BucketConfig(**settings)


def policy(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


# --- a clean bill of health --------------------------------------------------

def test_hardened_bucket_in_hardened_account_has_no_findings():
    assert run_checks(account(ALL_ON), [hardened()]) == []


# --- PUBLIC_POLICY -----------------------------------------------------------

def test_public_policy_is_high():
    bucket = hardened(public_access_block=None, policy=policy(PUBLIC_READ, DENY_HTTP))
    finding = check_public_policy(bucket, account())
    assert finding.severity == "HIGH"
    assert "s3:GetObject" in finding.detail


def test_public_policy_long_principal_form():
    statement = dict(PUBLIC_READ, Principal={"AWS": "*"})
    bucket = hardened(public_access_block=None, policy=policy(statement))
    assert check_public_policy(bucket, account()).severity == "HIGH"


def test_policy_with_condition_is_not_public():
    statement = dict(PUBLIC_READ, Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
    bucket = hardened(public_access_block=None, policy=policy(statement))
    assert check_public_policy(bucket, account()) is None


def test_policy_for_specific_account_is_not_public():
    statement = dict(PUBLIC_READ, Principal={"AWS": "arn:aws:iam::111122223333:root"})
    bucket = hardened(public_access_block=None, policy=policy(statement))
    assert check_public_policy(bucket, account()) is None


def test_public_policy_overridden_by_account_bpa_is_low():
    bucket = hardened(public_access_block=None, policy=policy(PUBLIC_READ))
    finding = check_public_policy(bucket, account(ALL_ON))
    assert finding.severity == "LOW"
    assert "overriding" in finding.detail


def test_single_statement_policy_not_in_a_list():
    bucket = hardened(public_access_block=None, policy={"Statement": PUBLIC_READ})
    assert check_public_policy(bucket, account()) is not None


# --- PUBLIC_ACL --------------------------------------------------------------

def _grant(uri: str, permission: str = "READ") -> dict:
    return {"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}


def test_public_acl_all_users():
    bucket = hardened(public_access_block=None, object_ownership="ObjectWriter", acl_grants=[_grant(ALL_USERS)])
    finding = check_public_acl(bucket, account())
    assert finding.severity == "HIGH"
    assert "READ to everyone" in finding.detail


def test_public_acl_authenticated_users_means_any_aws_account():
    bucket = hardened(
        public_access_block=None, object_ownership="ObjectWriter",
        acl_grants=[_grant(AUTHENTICATED_USERS, "WRITE")],
    )
    assert "WRITE to any AWS account" in check_public_acl(bucket, account()).detail


def test_public_acl_has_no_effect_when_acls_disabled():
    bucket = hardened(public_access_block=None, acl_grants=[_grant(ALL_USERS)])  # BucketOwnerEnforced
    assert check_public_acl(bucket, account()) is None


def test_public_acl_ignored_by_bpa():
    bucket = hardened(object_ownership="ObjectWriter", acl_grants=[_grant(ALL_USERS)])  # IgnorePublicAcls on
    assert check_public_acl(bucket, account()) is None


def test_owner_only_acl_is_fine():
    owner = {"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"}
    bucket = hardened(public_access_block=None, object_ownership="ObjectWriter", acl_grants=[owner])
    assert check_public_acl(bucket, account()) is None


# --- Block Public Access -----------------------------------------------------

def test_account_bpa_missing_entirely():
    finding = check_account_bpa(account(None))
    assert finding.rule == "ACCOUNT_BPA_OFF"
    assert all(flag in finding.detail for flag in BPA_FLAGS)


def test_account_bpa_partial_lists_only_missing_flags():
    finding = check_account_bpa(account(dict(ALL_ON, BlockPublicPolicy=False)))
    assert finding.detail.endswith("BlockPublicPolicy")


def test_bucket_bpa_not_needed_when_account_covers_it():
    assert check_bucket_bpa(hardened(public_access_block=None), account(ALL_ON)) is None


def test_bucket_bpa_flagged_when_account_doesnt_cover_it():
    bucket = hardened(public_access_block=dict(ALL_ON, RestrictPublicBuckets=False))
    finding = check_bucket_bpa(bucket, account())
    assert finding.detail.endswith("RestrictPublicBuckets")


# --- NO_TLS_ENFORCEMENT ------------------------------------------------------

def test_no_policy_means_no_tls_enforcement():
    assert check_tls(hardened(policy=None), account()).rule == "NO_TLS_ENFORCEMENT"


def test_tls_condition_variants_are_recognized():
    # AWS accepts the value as a string, a JSON boolean, or a list, and the key in any case.
    for condition in (
        {"Bool": {"aws:SecureTransport": False}},
        {"Bool": {"aws:SecureTransport": ["false"]}},
        {"Bool": {"aws:securetransport": "false"}},
    ):
        bucket = hardened(policy=policy(dict(DENY_HTTP, Condition=condition)))
        assert check_tls(bucket, account()) is None, condition


def test_allow_with_securetransport_true_is_not_enforcement():
    statement = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Condition": {"Bool": {"aws:SecureTransport": "true"}}}
    assert check_tls(hardened(policy=policy(statement)), account()) is not None


# --- encryption, versioning, logging, ACLs ----------------------------------

def test_no_default_encryption():
    assert check_encryption(hardened(encryption=None), account()).severity == "MEDIUM"


def test_suspended_versioning_is_flagged():
    assert "suspended" in check_versioning(hardened(versioning="Suspended"), account()).detail


def test_logging_off():
    assert check_logging(hardened(logging_enabled=False), account()).rule == "ACCESS_LOGGING_OFF"


def test_acls_enabled_when_ownership_not_set():
    assert "not set" in check_acls_enabled(hardened(object_ownership=None), account()).detail


# --- couldn't-check means skipped, not failed --------------------------------

def test_access_denied_skips_the_check_instead_of_guessing():
    bucket = hardened(
        policy=None, encryption=None, versioning="Disabled", logging_enabled=False,
        errors={"policy": "AccessDenied", "encryption": "AccessDenied",
                "versioning": "AccessDenied", "logging": "AccessDenied"},
    )
    assert run_checks(account(ALL_ON), [bucket]) == []


# --- ordering ----------------------------------------------------------------

def test_findings_sorted_most_severe_first():
    risky = hardened(name="risky", public_access_block=None, policy=policy(PUBLIC_READ), versioning="Disabled")
    severities = [f.severity for f in run_checks(account(), [risky])]
    assert severities == sorted(severities, key=["HIGH", "MEDIUM", "LOW"].index)
    assert severities[0] == "HIGH"
