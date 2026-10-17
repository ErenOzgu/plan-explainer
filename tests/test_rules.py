import json

import pytest

from plan_explainer.config import Config
from plan_explainer.rules import RULES, judge_exposure

from .builders import findings, load, plan_json, rc, rule_ids

WORLD = ["0.0.0.0/0"]


def fw(ports=("22",), protocol="tcp", sources=WORLD, **extra):
    allow = {"protocol": protocol}
    if ports is not None:
        allow["ports"] = list(ports)
    return {"name": "fw", "allow": [allow], "source_ranges": sources, **extra}


def sev(found):
    return [(f.rule, f.severity) for f in found]


# --- open-ingress ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("after", "expected"),
    [
        (fw(["22"]), [("open-ingress", "high")]),
        (fw(["3389"]), [("open-ingress", "high")]),
        (fw(["5432"]), [("open-ingress", "high")]),
        (fw(["80", "443"]), []),
        (fw(["443"], sources=["10.0.0.0/8"]), []),
        (fw(["22"], sources=["10.0.0.0/8", "192.168.0.0/16"]), []),
        (fw(["8080"]), [("open-ingress", "low")]),
        (fw(None), [("open-ingress", "high")]),
        (fw([]), [("open-ingress", "high")]),
        (fw(None, protocol="all"), [("open-ingress", "high")]),
        (fw(["0-65535"]), [("open-ingress", "high")]),
        (fw(["8000-9100"]), [("open-ingress", "medium")]),
        (fw(["20-30"]), [("open-ingress", "high")]),
        (fw(["53"], protocol="udp"), [("open-ingress", "low")]),
        (fw(None, protocol="icmp"), []),
        (fw(["22"], disabled=True), []),
        (fw(["22"], direction="EGRESS"), []),
        (fw(["22"], direction="INGRESS"), [("open-ingress", "high")]),
        (fw(["22"], sources=["::/0"]), [("open-ingress", "high")]),
        (fw(["nonsense"]), []),
    ],
)
def test_google_firewalls(after, expected):
    assert sev(findings("google_compute_firewall", after)) == expected


def test_a_firewall_without_a_direction_is_ingress_and_without_sources_nothing():
    assert findings("google_compute_firewall", {"allow": [{"protocol": "tcp", "ports": ["22"]}]}) == []


def test_several_allow_blocks_make_one_finding_with_the_worst_severity():
    after = {
        "source_ranges": WORLD,
        "allow": [{"protocol": "tcp", "ports": ["8080"]}, {"protocol": "tcp", "ports": ["22"]}],
    }
    (f,) = findings("google_compute_firewall", after)
    assert f.severity == "high"
    assert "SSH (22)" in f.title and "TCP 8080" in f.title


def test_the_evidence_names_the_values():
    (f,) = findings("google_compute_firewall", fw(["22"]))
    assert 'source_ranges = ["0.0.0.0/0"]' in f.evidence
    assert 'allow = [{"ports": ["22"], "protocol": "tcp"}]' in f.evidence


def test_a_plan_that_destroys_the_firewall_raises_nothing():
    assert findings("google_compute_firewall", None, ("delete",), before=fw(["22"])) == []


def test_updates_are_judged_on_the_planned_values():
    assert sev(
        findings(
            "google_compute_firewall", fw(["22"]), ("update",), before=fw(["22"], sources=["10.0.0.0/8"])
        )
    ) == [("open-ingress", "high")]


def aws_ingress(**kw):
    base = {"cidr_blocks": [], "ipv6_cidr_blocks": [], "protocol": "tcp", "from_port": 22, "to_port": 22}
    return {**base, **kw}


@pytest.mark.parametrize(
    ("ingress", "expected"),
    [
        (aws_ingress(cidr_blocks=WORLD), [("open-ingress", "high")]),
        (aws_ingress(ipv6_cidr_blocks=["::/0"]), [("open-ingress", "high")]),
        (aws_ingress(cidr_blocks=WORLD, protocol="-1", from_port=0, to_port=0), [("open-ingress", "high")]),
        (aws_ingress(cidr_blocks=WORLD, from_port=443, to_port=443), []),
        (aws_ingress(cidr_blocks=["10.0.0.0/8"]), []),
        (aws_ingress(cidr_blocks=WORLD, protocol="icmp", from_port=-1, to_port=-1), []),
        (aws_ingress(cidr_blocks=WORLD, from_port=0, to_port=65535), [("open-ingress", "high")]),
    ],
)
def test_aws_security_groups(ingress, expected):
    assert (
        sev(
            findings("aws_security_group", {"ingress": [ingress], "egress": [aws_ingress(cidr_blocks=WORLD)]})
        )
        == expected
    )


def test_aws_rule_resources():
    assert sev(
        findings("aws_security_group_rule", {"type": "ingress", **aws_ingress(cidr_blocks=WORLD)})
    ) == [("open-ingress", "high")]
    assert findings("aws_security_group_rule", {"type": "egress", **aws_ingress(cidr_blocks=WORLD)}) == []
    new = {"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "tcp", "from_port": 3306, "to_port": 3306}
    assert sev(findings("aws_vpc_security_group_ingress_rule", new)) == [("open-ingress", "high")]
    assert findings("aws_vpc_security_group_ingress_rule", {**new, "cidr_ipv4": "10.0.0.0/8"}) == []


def test_exposure_judgement_directly():
    assert judge_exposure("tcp", [(22, 22)]) == ("high", "SSH (22)")
    assert judge_exposure("tcp", [(22, 22), (3389, 3389)]) == ("high", "SSH (22), RDP (3389)")
    assert judge_exposure("tcp", [(443, 443)]) is None
    assert judge_exposure("tcp", [(8443, 8443)]) == ("low", "TCP 8443")
    assert judge_exposure("udp", [(22, 22)]) == ("low", "UDP 22")
    assert judge_exposure("esp", None) is None


# --- public-policy / broad-role / authoritative-iam -----------------------------------------------------


@pytest.mark.parametrize("member", ["allUsers", "allAuthenticatedUsers"])
def test_public_members_on_any_google_iam_resource(member):
    f = findings("google_storage_bucket_iam_member", {"role": "roles/storage.objectViewer", "member": member})
    assert sev(f) == [("public-policy", "high")]
    assert member in f[0].title


def test_public_members_in_bindings_and_policies():
    found = findings(
        "google_project_iam_binding", {"role": "roles/viewer", "members": ["user:a@b.c", "allUsers"]}
    )
    assert sev(found) == [("public-policy", "high"), ("authoritative-iam", "low")]
    doc = json.dumps({"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]})
    assert sev(findings("google_storage_bucket_iam_policy", {"policy_data": doc})) == [
        ("public-policy", "high"),
        ("authoritative-iam", "medium"),
    ]


def test_named_members_are_fine():
    assert (
        findings(
            "google_storage_bucket_iam_member", {"role": "roles/storage.objectViewer", "member": "user:a@b.c"}
        )
        == []
    )


def pol(**statement):
    base = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
    return json.dumps({"Version": "2012-10-17", "Statement": [{**base, **statement}]})


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ({"Principal": "*"}, [("public-policy", "high")]),
        ({"Principal": {"AWS": "*"}}, [("public-policy", "high")]),
        ({"Principal": {"AWS": ["*"]}}, [("public-policy", "high")]),
        ({"Principal": "*", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}, []),
        ({"Principal": "*", "Effect": "Deny"}, []),
        ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}, []),
    ],
)
def test_aws_bucket_policies(statement, expected):
    assert sev(findings("aws_s3_bucket_policy", {"policy": pol(**statement)})) == expected


def test_aws_trust_policies_and_junk():
    trust = pol(Principal="*", Action="sts:AssumeRole")
    (f,) = findings("aws_iam_role", {"assume_role_policy": trust})
    assert f.rule == "public-policy" and "assume this role" in f.detail
    assert findings("aws_s3_bucket_policy", {"policy": "not json"}) == []
    assert findings("aws_s3_bucket_policy", {"policy": None}) == []
    assert findings("aws_s3_bucket_policy", {"bucket": "b"}, after_unknown={"policy": True}) == []


@pytest.mark.parametrize(
    ("rtype", "role", "expected"),
    [
        ("google_project_iam_member", "roles/owner", ("broad-role", "high")),
        ("google_project_iam_member", "roles/editor", ("broad-role", "high")),
        ("google_folder_iam_member", "roles/resourcemanager.folderAdmin", ("broad-role", "high")),
        ("google_organization_iam_member", "roles/resourcemanager.organizationAdmin", ("broad-role", "high")),
        ("google_project_iam_member", "roles/iam.securityAdmin", ("broad-role", "high")),
        ("google_project_iam_member", "roles/iam.serviceAccountTokenCreator", ("broad-role", "medium")),
        ("google_project_iam_member", "roles/iam.serviceAccountUser", ("broad-role", "medium")),
    ],
)
def test_broad_google_roles_on_a_whole_scope(rtype, role, expected):
    assert sev(findings(rtype, {"role": role, "member": "serviceAccount:ci@p.iam.gserviceaccount.com"})) == [
        expected
    ]


def test_narrow_or_resource_level_roles_are_fine():
    sa = "serviceAccount:ci@p.iam.gserviceaccount.com"
    assert findings("google_project_iam_member", {"role": "roles/viewer", "member": sa}) == []
    assert findings("google_project_iam_member", {"role": "roles/storage.objectAdmin", "member": sa}) == []
    # serviceAccountUser on one service account is the normal way to let something act as it
    assert (
        findings("google_service_account_iam_member", {"role": "roles/iam.serviceAccountUser", "member": sa})
        == []
    )
    assert findings("google_storage_bucket_iam_member", {"role": "roles/owner", "member": sa}) == []


def test_owner_for_everyone_is_one_public_finding_not_two():
    assert rule_ids(findings("google_project_iam_member", {"role": "roles/owner", "member": "allUsers"})) == [
        "public-policy"
    ]


def test_the_member_is_in_the_evidence():
    (f,) = findings("google_project_iam_member", {"role": "roles/owner", "member": "user:a@b.c"})
    assert 'member = "user:a@b.c"' in f.evidence


def test_aws_admin_policies():
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    for rtype in (
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_policy_attachment",
    ):
        assert sev(findings(rtype, {"policy_arn": arn})) == [("broad-role", "high")]
    assert (
        findings("aws_iam_role_policy_attachment", {"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
        == []
    )
    assert sev(findings("aws_iam_policy", {"policy": pol(Action="*", Resource="*")})) == [
        ("broad-role", "high")
    ]
    assert sev(findings("aws_iam_policy", {"policy": pol(Action=["iam:*"], Resource="*")})) == [
        ("broad-role", "high")
    ]
    assert sev(findings("aws_iam_policy", {"policy": pol(Action="s3:*", Resource="*")})) == [
        ("broad-role", "medium")
    ]
    assert findings("aws_iam_policy", {"policy": pol(Action="s3:*", Resource="arn:aws:s3:::b/*")}) == []
    assert findings("aws_iam_policy", {"policy": pol(Action="sts:AssumeRole", Resource="*")}) == []
    assert findings("aws_iam_policy", {"policy": pol(Action="*", Resource="*", Effect="Deny")}) == []


def test_authoritative_iam():
    assert sev(findings("google_project_iam_policy", {"policy_data": "{}"})) == [
        ("authoritative-iam", "medium")
    ]
    assert sev(
        findings("google_project_iam_binding", {"role": "roles/viewer", "members": ["user:a@b.c"]})
    ) == [("authoritative-iam", "low")]
    assert findings("google_project_iam_member", {"role": "roles/viewer", "member": "user:a@b.c"}) == []


# --- storage and endpoints ------------------------------------------------------------------------------


def test_public_storage():
    assert sev(findings("aws_s3_bucket_acl", {"acl": "public-read"})) == [("public-storage", "high")]
    assert sev(findings("aws_s3_bucket", {"acl": "public-read-write"})) == [("public-storage", "high")]
    assert findings("aws_s3_bucket_acl", {"acl": "private"}) == []
    block = {
        k: True
        for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    }
    assert findings("aws_s3_bucket_public_access_block", block) == []
    (f,) = findings("aws_s3_bucket_public_access_block", {**block, "block_public_policy": False})
    assert (f.severity, f.evidence) == ("medium", ("block_public_policy = false",))
    assert sev(findings("google_storage_bucket", {"uniform_bucket_level_access": False})) == [
        ("public-storage", "low")
    ]
    assert findings("google_storage_bucket", {"uniform_bucket_level_access": True}) == []


def sql(networks=(), **extra):
    return {
        "settings": [{"ip_configuration": [{"authorized_networks": [{"value": n} for n in networks]}]}],
        **extra,
    }


def test_public_endpoints():
    assert sev(findings("google_sql_database_instance", sql(["0.0.0.0/0"]))) == [("public-endpoint", "high")]
    assert findings("google_sql_database_instance", sql(["10.0.0.0/8"])) == []
    assert findings("google_sql_database_instance", sql([])) == []
    gke = {"master_authorized_networks_config": [{"cidr_blocks": [{"cidr_block": "0.0.0.0/0"}]}]}
    assert sev(findings("google_container_cluster", gke)) == [("public-endpoint", "high")]
    ok = {"master_authorized_networks_config": [{"cidr_blocks": [{"cidr_block": "203.0.113.0/24"}]}]}
    assert findings("google_container_cluster", ok) == []
    assert sev(findings("aws_db_instance", {"publicly_accessible": True})) == [("public-endpoint", "high")]
    assert findings("aws_db_instance", {"publicly_accessible": False}) == []
    eks = {"vpc_config": [{"public_access_cidrs": WORLD, "endpoint_public_access": True}]}
    assert sev(findings("aws_eks_cluster", eks)) == [("public-endpoint", "medium")]
    eks_private = {"vpc_config": [{"public_access_cidrs": WORLD, "endpoint_public_access": False}]}
    assert findings("aws_eks_cluster", eks_private) == []


# --- data loss and protection ---------------------------------------------------------------------------


def test_destroying_data_is_high_and_says_what_is_lost():
    (f,) = findings(
        "google_sql_database_instance",
        None,
        ("delete",),
        before={"name": "db"},
        reason="delete_because_no_resource_config",
    )
    assert (f.rule, f.severity, f.title) == ("data-loss", "high", "will be destroyed")
    assert "the database and its data" in f.detail and "no longer in the configuration" in f.detail


def test_replacing_data_names_the_argument_that_forces_it():
    f = findings(
        "google_compute_disk",
        {"name": "d"},
        ("delete", "create"),
        before={"name": "d"},
        replace_paths=[["type"]],
    )
    assert (f[0].rule, f[0].severity) == ("data-loss", "high")
    assert "forced by type" in f[0].detail and "Nothing is copied" in f[0].detail


def test_create_before_destroy_is_described_as_such():
    (f,) = findings("aws_db_instance", {}, ("create", "delete"), before={})
    assert "created first" in f.detail and "Nothing is copied" in f.detail


def test_creating_or_updating_stateful_resources_is_not_data_loss():
    assert "data-loss" not in rule_ids(findings("google_sql_database_instance", {"name": "d"}))
    assert "data-loss" not in rule_ids(
        findings("google_sql_database_instance", {"name": "d"}, ("update",), before={"name": "d"})
    )


def test_other_resources_and_configured_types():
    assert findings("google_compute_firewall", None, ("delete",), before={}) == []
    assert findings("acme_widget", None, ("delete",), before={}) == []
    cfg = Config(stateful_types=frozenset({"acme_widget"}))
    assert sev(findings("acme_widget", None, ("delete",), before={}, cfg=cfg)) == [("data-loss", "high")]


def test_reserved_addresses_and_dns_are_medium():
    assert sev(findings("google_compute_address", None, ("delete",), before={})) == [("data-loss", "medium")]
    assert sev(findings("aws_route53_zone", None, ("delete",), before={})) == [("data-loss", "medium")]


def test_destroying_a_key_says_data_becomes_unreadable():
    (f,) = findings("google_kms_crypto_key", None, ("delete",), before={})
    assert "unreadable" in f.detail


def many_deletes(n):
    return [rc("google_compute_firewall", f"f{i}", ("delete",), before={}) for i in range(n)]


def test_mass_destroy_threshold():
    from plan_explainer.analysis import analyse

    assert [f.rule for f in analyse(load(*many_deletes(9))).findings] == []
    (f,) = analyse(load(*many_deletes(10))).findings
    assert (f.rule, f.severity, f.address) == ("mass-destroy", "medium", "(plan)")
    assert [f.rule for f in analyse(load(*many_deletes(3)), Config(mass_destroy=3)).findings] == [
        "mass-destroy"
    ]
    replaced = [
        rc("google_compute_firewall", f"r{i}", ("delete", "create"), before={}, after={}) for i in range(10)
    ]
    assert [f.rule for f in analyse(load(*replaced)).findings] == ["mass-destroy"]


def test_protection_switched_off_and_created_off():
    off = findings(
        "google_sql_database_instance",
        {"deletion_protection": False},
        ("update",),
        before={"deletion_protection": True},
    )
    assert sev(off) == [("protection-removed", "medium")]
    assert off[0].evidence == ("deletion_protection: true → false",)
    assert sev(findings("google_sql_database_instance", {"deletion_protection": False})) == [
        ("protection-removed", "low")
    ]
    assert findings("google_sql_database_instance", {"deletion_protection": True}) == []
    assert findings("google_pubsub_topic", {"deletion_protection": False}) == []
    assert sev(
        findings(
            "aws_lb",
            {"enable_deletion_protection": False},
            ("update",),
            before={"enable_deletion_protection": True},
        )
    ) == [("protection-removed", "medium")]
    assert (
        findings(
            "google_sql_database_instance",
            {"deletion_protection": False},
            ("update",),
            before={"deletion_protection": False},
        )
        == []
    )


def test_destroying_a_database_without_a_final_snapshot():
    f = findings("aws_db_instance", None, ("delete",), before={"skip_final_snapshot": True})
    assert ("no-final-snapshot", "high") in sev(f)
    assert "no-final-snapshot" not in rule_ids(
        findings("aws_db_instance", None, ("delete",), before={"skip_final_snapshot": False})
    )
    assert "no-final-snapshot" not in rule_ids(findings("aws_db_instance", {"skip_final_snapshot": True}))


def test_encryption_only_when_explicitly_off():
    assert sev(findings("aws_ebs_volume", {"encrypted": False})) == [("unencrypted", "medium")]
    assert sev(findings("aws_db_instance", {"storage_encrypted": False})) == [("unencrypted", "medium")]
    assert findings("aws_ebs_volume", {"encrypted": True}) == []
    assert findings("aws_ebs_volume", {"size": 10}) == []


def test_backups():
    off = {"settings": [{"backup_configuration": [{"enabled": False}]}]}
    assert sev(findings("google_sql_database_instance", off)) == [("backups-off", "medium")]
    on = {"settings": [{"backup_configuration": [{"enabled": True}]}]}
    assert findings("google_sql_database_instance", on) == []
    assert sev(findings("aws_db_instance", {"backup_retention_period": 0})) == [("backups-off", "medium")]
    assert findings("aws_db_instance", {"backup_retention_period": 7}) == []


def test_long_lived_keys():
    assert sev(findings("google_service_account_key", {})) == [("long-lived-credential", "medium")]
    assert sev(findings("aws_iam_access_key", {})) == [("long-lived-credential", "medium")]
    assert findings("google_service_account_key", None, ("delete",), before={}) == []


def test_vm_rules():
    full = {"service_account": [{"scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]}
    assert sev(findings("google_compute_instance", full)) == [("vm-broad-access", "medium")]
    assert sev(
        findings("google_compute_instance", {"service_account": [{"scopes": ["cloud-platform"]}]})
    ) == [("vm-broad-access", "medium")]
    narrow = {"service_account": [{"scopes": ["https://www.googleapis.com/auth/logging.write"]}]}
    assert findings("google_compute_instance", narrow) == []
    assert sev(
        findings("google_compute_instance", {"network_interface": [{"access_config": [{"nat_ip": None}]}]})
    ) == [("vm-public-ip", "low")]
    assert findings("google_compute_instance", {"network_interface": [{"access_config": []}]}) == []
    assert sev(findings("aws_instance", {"associate_public_ip_address": True})) == [("vm-public-ip", "low")]


# --- the rules as a set ---------------------------------------------------------------------------------


def test_every_rule_is_documented_and_has_a_positive_test():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids)) == 15
    src = open(__file__).read()
    for r in RULES:
        assert r.summary and r.covers
        assert f'"{r.id}"' in src, f"no test mentions {r.id}"


def test_evidence_never_shows_a_sensitive_value():
    after = fw(["22"])
    (f,) = findings("google_compute_firewall", after, after_sensitive={"source_ranges": True})
    assert "0.0.0.0/0" not in " ".join(f.evidence)
    assert "(sensitive)" in " ".join(f.evidence)


def test_findings_come_out_in_the_same_order_every_time():
    from plan_explainer.analysis import analyse

    changes = [
        rc("google_project_iam_member", "owner", after={"role": "roles/owner", "member": "user:a@b.c"}),
        rc("google_compute_firewall", "ssh", after=fw(["22"])),
        rc("google_compute_firewall", "alt", after=fw(["8080"])),
        rc("google_sql_database_instance", "db", ("delete",), before={}),
    ]
    first = [(f.severity, f.address) for f in analyse(load(*changes)).findings]
    second = [(f.severity, f.address) for f in analyse(load(*reversed(changes))).findings]
    assert first == second
    assert first == [
        ("high", "google_compute_firewall.ssh"),
        ("high", "google_project_iam_member.owner"),
        ("high", "google_sql_database_instance.db"),
        ("low", "google_compute_firewall.alt"),
    ]


def test_plan_json_helper_used_here_is_real_enough():
    assert plan_json()["format_version"] == "1.2"
