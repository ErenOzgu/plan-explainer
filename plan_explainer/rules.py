"""The rules: plain code that reads the planned values and returns findings. No model is involved."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import Config
from .model import Change, Plan
from .values import leaves, show

SEVERITIES = ("high", "medium", "low")
RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    address: str
    title: str
    detail: str
    advice: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: str
    summary: str
    covers: str


RULES: list[RuleInfo] = []
_CHANGE_RULES: dict[str, Callable[[Change, Config], list[Finding]]] = {}
_PLAN_RULES: dict[str, Callable[[Plan, Config], list[Finding]]] = {}


def rule(rule_id: str, severity: str, summary: str, covers: str):
    def deco(fn):
        RULES.append(RuleInfo(rule_id, severity, summary, covers))
        _CHANGE_RULES[rule_id] = fn
        return fn

    return deco


def plan_rule(rule_id: str, severity: str, summary: str, covers: str):
    def deco(fn):
        RULES.append(RuleInfo(rule_id, severity, summary, covers))
        _PLAN_RULES[rule_id] = fn
        return fn

    return deco


def rule_ids() -> set[str]:
    return {r.id for r in RULES}


def _f(
    rule_id: str, severity: str, ch: Change, title: str, detail: str, advice: str, *evidence: str
) -> Finding:
    return Finding(rule_id, severity, ch.address, title, detail, advice, tuple(evidence))


def _ev(ch: Change, name: str, *keys: str, many: bool = False) -> str:
    """'name = value' for the values at keys, with sensitive parts hidden; many=True always shows a list."""
    obj, mask = ch.after, ch.after_sensitive
    vals = list(leaves(obj, keys, mask)) if isinstance(obj, dict) else []
    return f"{name} = {show(vals[0] if len(vals) == 1 and not many else vals)}"


def _planned(ch: Change) -> bool:
    """The change leaves something in place whose planned values can be judged."""
    return ch.mode == "managed" and ch.kind in ("create", "update", "replace") and isinstance(ch.after, dict)


def _worst(items: list[tuple[str, str]]) -> tuple[str, str]:
    return min(items, key=lambda i: RANK[i[0]])[0], "; ".join(dict.fromkeys(t for _, t in items))


WORLD = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "SQL Server",
    2375: "Docker API",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
WEB_PORTS = {80, 443}


def _ports(spec: Any) -> tuple[int, int] | None:
    m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", str(spec))
    if not m:
        return None
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    return (lo, hi) if lo <= hi else None


def judge_exposure(protocol: str, ranges: list[tuple[int, int]] | None) -> tuple[str, str] | None:
    """How bad it is to let the whole internet reach these ports; None when it is ordinary."""
    proto = str(protocol).lower()
    if proto in ("all", "-1"):
        return "high", "all protocols and ports"
    if proto not in ("tcp", "udp", "sctp"):
        return None
    if not ranges:
        return "high", f"all {proto.upper()} ports"
    total = sum(hi - lo + 1 for lo, hi in ranges)
    if total >= 65000:
        return "high", f"all {proto.upper()} ports"
    if proto == "tcp":
        hits = [
            f"{name} ({port})"
            for port, name in sorted(SENSITIVE_PORTS.items())
            if any(lo <= port <= hi for lo, hi in ranges)
        ]
        if hits:
            return "high", ", ".join(hits)
    if total >= 1000:
        return "medium", f"{total} {proto.upper()} ports"
    if proto == "tcp" and all(lo == hi and lo in WEB_PORTS for lo, hi in ranges):
        return None
    text = ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ranges)
    return "low", f"{proto.upper()} {text}"


def _world(values: list[Any]) -> list[str]:
    return sorted({v for v in values if isinstance(v, str) and v in WORLD})


# --- open-ingress ---------------------------------------------------------------------------------------


def _aws_ranges(lo: Any, hi: Any) -> list[tuple[int, int]] | None:
    if isinstance(lo, int) and isinstance(hi, int) and not isinstance(lo, bool):
        return [(lo, hi)] if lo <= hi else None
    return None


@rule(
    "open-ingress",
    "high / medium / low",
    "Lets the whole internet (0.0.0.0/0 or ::/0) reach SSH, RDP, a database port, all ports, or other non-web ports.",
    "google_compute_firewall, aws_security_group, aws_security_group_rule, aws_vpc_security_group_ingress_rule",
)
def open_ingress(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    a = ch.after
    judged: list[tuple[str, str]] = []
    sources: list[str] = []
    if ch.type == "google_compute_firewall":
        if a.get("disabled") is True or a.get("direction") not in (None, "INGRESS"):
            return []
        sources = _world(ch.after_values("source_ranges"))
        for allow in a.get("allow") or []:
            given = allow.get("ports") or []
            ranges = [r for r in map(_ports, given) if r]
            if given and not ranges:
                continue  # ports we cannot read: say nothing rather than guess
            j = judge_exposure(allow.get("protocol", ""), ranges)
            if j and sources:
                judged.append(j)
    elif ch.type == "aws_security_group":
        for rule_ in a.get("ingress") or []:
            src = _world((rule_.get("cidr_blocks") or []) + (rule_.get("ipv6_cidr_blocks") or []))
            j = judge_exposure(
                rule_.get("protocol", ""), _aws_ranges(rule_.get("from_port"), rule_.get("to_port"))
            )
            if src and j:
                sources += src
                judged.append(j)
    elif ch.type == "aws_security_group_rule" and a.get("type") == "ingress":
        sources = _world((a.get("cidr_blocks") or []) + (a.get("ipv6_cidr_blocks") or []))
        j = judge_exposure(a.get("protocol", ""), _aws_ranges(a.get("from_port"), a.get("to_port")))
        if sources and j:
            judged.append(j)
    elif ch.type == "aws_vpc_security_group_ingress_rule":
        sources = _world([a.get("cidr_ipv4"), a.get("cidr_ipv6")])
        j = judge_exposure(a.get("ip_protocol", ""), _aws_ranges(a.get("from_port"), a.get("to_port")))
        if sources and j:
            judged.append(j)
    if not judged:
        return []
    severity, text = _worst(judged)
    where = ", ".join(sorted(set(sources)))
    return [
        _f(
            "open-ingress",
            severity,
            ch,
            f"{text} open to the internet",
            f"Allows inbound traffic from {where} to: {text}.",
            "Restrict the source range to the networks that need access (a VPN, an office range, an identity-aware proxy).",
            *(
                [_ev(ch, "source_ranges", "source_ranges", many=True), _ev(ch, "allow", "allow", many=True)]
                if ch.type == "google_compute_firewall"
                else [f"source = {where}"]
            ),
        )
    ]


# --- public-policy, broad-role, authoritative-iam -------------------------------------------------------

GCP_IAM = re.compile(r"^google_.+_iam_(member|binding|policy)$")
GCP_SCOPED_IAM = re.compile(r"^google_(project|folder|organization)_iam_(member|binding|policy)$")
PUBLIC_MEMBERS = {
    "allUsers": "everyone on the internet",
    "allAuthenticatedUsers": "anyone with any Google account",
}


def _gcp_grants(ch: Change) -> list[tuple[str, str]]:
    a = ch.after
    if ch.type.endswith("_iam_member"):
        return [(a.get("role"), a.get("member"))] if a.get("role") and a.get("member") else []
    if ch.type.endswith("_iam_binding"):
        return [(a.get("role"), m) for m in a.get("members") or [] if a.get("role") and isinstance(m, str)]
    try:
        doc = json.loads(a.get("policy_data") or "")
    except (TypeError, ValueError):
        return []
    out = []
    for b in doc.get("bindings") or [] if isinstance(doc, dict) else []:
        for m in b.get("members") or []:
            out.append((b.get("role"), m))
    return out


def _json_attr(ch: Change, name: str) -> dict | None:
    value = ch.after.get(name) if isinstance(ch.after, dict) else None
    try:
        doc = json.loads(value) if isinstance(value, str) else None
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _statements(doc: dict) -> list[dict]:
    st = doc.get("Statement")
    st = [st] if isinstance(st, dict) else st
    return [s for s in st or [] if isinstance(s, dict)]


def _as_list(x: Any) -> list:
    return x if isinstance(x, list) else ([] if x is None else [x])


def _public_principal(p: Any) -> bool:
    if p == "*":
        return True
    return isinstance(p, dict) and "*" in _as_list(p.get("AWS"))


@rule(
    "public-policy",
    "high",
    'Grants access to allUsers or allAuthenticatedUsers (Google Cloud), or to Principal "*" with no condition (AWS policy documents).',
    "google_*_iam_member / _binding / _policy, aws_* with policy or assume_role_policy",
)
def public_policy(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    out = []
    if GCP_IAM.match(ch.type):
        for role, member in _gcp_grants(ch):
            if member in PUBLIC_MEMBERS:
                out.append(
                    _f(
                        "public-policy",
                        "high",
                        ch,
                        f"{role} granted to {member}",
                        f"Gives {PUBLIC_MEMBERS[member]} the role {role}.",
                        "Grant the role to specific identities, or serve public content through a load balancer or CDN.",
                        f"role = {show(role)}",
                        f"member = {show(member)}",
                    )
                )
    elif ch.type.startswith("aws_"):
        for attr in ("policy", "assume_role_policy"):
            doc = _json_attr(ch, attr)
            for st in _statements(doc or {}):
                if (
                    st.get("Effect") == "Allow"
                    and _public_principal(st.get("Principal"))
                    and not st.get("Condition")
                ):
                    what = (
                        "assume this role"
                        if attr == "assume_role_policy"
                        else "use the actions in this policy"
                    )
                    out.append(
                        _f(
                            "public-policy",
                            "high",
                            ch,
                            f'{attr} allows Principal "*" with no condition',
                            f"Any AWS principal can {what} ({', '.join(map(str, _as_list(st.get('Action')))) or 'no actions listed'}).",
                            "Name the principals, or add a condition such as aws:PrincipalOrgID or aws:SourceVpce.",
                            f"{attr}.Principal = {show(st.get('Principal'))}",
                        )
                    )
                    break
    return out


HIGH_ROLES = {
    "roles/owner": "gets full control of everything in the scope",
    "roles/editor": "gets write access to almost every service in the scope",
    "roles/resourcemanager.projectIamAdmin": "can grant any role in the project, including to itself",
    "roles/resourcemanager.folderAdmin": "gets full control of the folder",
    "roles/resourcemanager.organizationAdmin": "can change the IAM policy of the whole organization",
    "roles/iam.securityAdmin": "can grant any role, including to itself",
}
MEDIUM_ROLES = {
    "roles/iam.serviceAccountUser": "can run workloads as any service account in the scope",
    "roles/iam.serviceAccountTokenCreator": "can impersonate any service account in the scope",
    "roles/iam.serviceAccountAdmin": "can create and manage service accounts",
    "roles/iam.serviceAccountKeyAdmin": "can create keys for any service account",
}
AWS_ATTACHMENTS = {
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
}


@rule(
    "broad-role",
    "high / medium",
    "Grants owner, editor, or an IAM-admin role on a whole project, folder or organization; or an AWS policy that allows every action on every resource.",
    "google_(project|folder|organization)_iam_*, aws_iam_*policy*, aws_iam_*_policy_attachment",
)
def broad_role(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    out = []
    if GCP_SCOPED_IAM.match(ch.type):
        for role, member in _gcp_grants(ch):
            table = HIGH_ROLES if role in HIGH_ROLES else MEDIUM_ROLES if role in MEDIUM_ROLES else None
            if table is not None and member not in PUBLIC_MEMBERS:
                scope = ch.type.split("_")[1]
                out.append(
                    _f(
                        "broad-role",
                        "high" if table is HIGH_ROLES else "medium",
                        ch,
                        f"{role} on a whole {scope}",
                        f"{member} {table[role]}.",
                        "Use a narrower predefined or custom role, or grant it on the one resource that needs it.",
                        f"role = {show(role)}",
                        f"member = {show(member)}",
                    )
                )
    elif ch.type in AWS_ATTACHMENTS:
        arn = ch.after.get("policy_arn")
        if isinstance(arn, str) and arn.endswith("/AdministratorAccess"):
            out.append(
                _f(
                    "broad-role",
                    "high",
                    ch,
                    "AdministratorAccess attached",
                    "The managed policy AdministratorAccess allows every action on every resource.",
                    "Attach a policy that lists only what is needed.",
                    f"policy_arn = {show(arn)}",
                )
            )
    elif ch.type.startswith("aws_") and ch.type not in AWS_ATTACHMENTS:
        doc = _json_attr(ch, "policy")
        verdicts = []
        for st in _statements(doc or {}):
            if st.get("Effect") != "Allow" or "*" not in _as_list(st.get("Resource")):
                continue
            actions = [str(x) for x in _as_list(st.get("Action"))]
            if any(x in ("*", "*:*") for x in actions):
                verdicts.append(("high", "allows every action on every resource (Action *, Resource *)"))
            elif any(x.lower() in ("iam:*", "sts:*") for x in actions):
                verdicts.append(
                    (
                        "high",
                        "allows every IAM or STS action on every resource, which includes granting itself anything",
                    )
                )
            elif any(x.endswith(":*") for x in actions):
                verdicts.append(("medium", "allows every action of a whole service on every resource"))
        if verdicts:
            severity, text = _worst(verdicts)
            out.append(
                _f(
                    "broad-role",
                    severity,
                    ch,
                    "policy is wider than any one job needs",
                    f"The policy {text}.",
                    "List the actions and the resources the workload needs.",
                    "policy.Statement[].Action/Resource contain a wildcard",
                )
            )
    return out


@rule(
    "authoritative-iam",
    "medium / low",
    "An IAM resource that owns a whole policy (_iam_policy) or a whole role (_iam_binding): members not listed are removed.",
    "google_*_iam_policy, google_*_iam_binding",
)
def authoritative_iam(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch) or not GCP_IAM.match(ch.type):
        return []
    if ch.type.endswith("_iam_policy"):
        return [
            _f(
                "authoritative-iam",
                "medium",
                ch,
                "replaces the whole IAM policy",
                "An _iam_policy resource is authoritative: every binding that is not in it is removed, including the ones that keep you in access.",
                "Use _iam_member unless this configuration really owns the complete policy.",
            )
        ]
    if ch.type.endswith("_iam_binding"):
        return [
            _f(
                "authoritative-iam",
                "low",
                ch,
                "owns every member of the role",
                f"An _iam_binding is authoritative for {show(ch.after.get('role'))}: members of that role that are not listed here are removed.",
                "Use _iam_member to add one member without touching the others.",
                _ev(ch, "role", "role"),
            )
        ]
    return []


# --- storage and endpoints ------------------------------------------------------------------------------

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
PUBLIC_BLOCKS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")


@rule(
    "public-storage",
    "high / medium / low",
    "A bucket with a public ACL, with S3 public-access blocks switched off, or without uniform bucket-level access.",
    "aws_s3_bucket, aws_s3_bucket_acl, aws_s3_bucket_public_access_block, google_storage_bucket",
)
def public_storage(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    a = ch.after
    if ch.type in ("aws_s3_bucket", "aws_s3_bucket_acl") and a.get("acl") in PUBLIC_ACLS:
        return [
            _f(
                "public-storage",
                "high",
                ch,
                f"bucket ACL {a['acl']}",
                "The ACL lets everyone (or every AWS account) read the objects in the bucket.",
                "Use a private ACL and share objects with presigned URLs or a CDN.",
                _ev(ch, "acl", "acl"),
            )
        ]
    if ch.type == "aws_s3_bucket_public_access_block":
        off = [k for k in PUBLIC_BLOCKS if a.get(k) is False]
        if off:
            return [
                _f(
                    "public-storage",
                    "medium",
                    ch,
                    "S3 public-access protections switched off",
                    f"{', '.join(off)} {'is' if len(off) == 1 else 'are'} false, so a public ACL or policy on the bucket would take effect.",
                    "Keep all four settings true unless the bucket is meant to be public.",
                    *[f"{k} = false" for k in off],
                )
            ]
    if ch.type == "google_storage_bucket" and a.get("uniform_bucket_level_access") is False:
        return [
            _f(
                "public-storage",
                "low",
                ch,
                "uniform bucket-level access is off",
                "Individual objects can be made public with their own ACLs, outside the bucket's IAM policy.",
                "Set uniform_bucket_level_access = true.",
                "uniform_bucket_level_access = false",
            )
        ]
    return []


@rule(
    "public-endpoint",
    "high / medium",
    "A database, cluster API or similar endpoint that is reachable from the internet.",
    "google_sql_database_instance, google_container_cluster, aws_db_instance, aws_rds_cluster_instance, aws_redshift_cluster, aws_eks_cluster",
)
def public_endpoint(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    t = ch.type
    if t == "google_sql_database_instance":
        nets = _world(ch.after_values("settings", "ip_configuration", "authorized_networks", "value"))
        if nets:
            return [
                _f(
                    "public-endpoint",
                    "high",
                    ch,
                    "database reachable from any address",
                    f"An authorized network of {nets[0]} lets any host try to connect to the instance's public IP.",
                    "Authorize only the addresses that need it, or use a private IP and the Cloud SQL connectors.",
                    _ev(
                        ch,
                        "authorized_networks",
                        "settings",
                        "ip_configuration",
                        "authorized_networks",
                        "value",
                    ),
                )
            ]
    if t == "google_container_cluster":
        nets = _world(ch.after_values("master_authorized_networks_config", "cidr_blocks", "cidr_block"))
        if nets:
            return [
                _f(
                    "public-endpoint",
                    "high",
                    ch,
                    "cluster API server reachable from any address",
                    f"master_authorized_networks_config allows {nets[0]}, so the Kubernetes API is open to the internet.",
                    "Authorize only your own ranges.",
                    _ev(ch, "cidr_block", "master_authorized_networks_config", "cidr_blocks", "cidr_block"),
                )
            ]
    if (
        t in ("aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster")
        and ch.after.get("publicly_accessible") is True
    ):
        return [
            _f(
                "public-endpoint",
                "high",
                ch,
                "database is publicly accessible",
                "publicly_accessible gives it a public IP address; only its security group stands between it and the internet.",
                "Put it in private subnets and set publicly_accessible = false.",
                "publicly_accessible = true",
            )
        ]
    if t == "aws_eks_cluster":
        cfg_ = ch.after_values("vpc_config", "public_access_cidrs")
        enabled = ch.after_values("vpc_config", "endpoint_public_access")
        if _world(cfg_) and (not enabled or enabled[0] is not False):
            return [
                _f(
                    "public-endpoint",
                    "medium",
                    ch,
                    "cluster API server reachable from any address",
                    "The public endpoint is enabled and public_access_cidrs includes 0.0.0.0/0.",
                    "Restrict public_access_cidrs, or turn the public endpoint off.",
                    _ev(ch, "public_access_cidrs", "vpc_config", "public_access_cidrs"),
                )
            ]
    return []


# --- data loss and protection ---------------------------------------------------------------------------

STATEFUL: dict[str, tuple[str, str]] = {
    "google_sql_database_instance": ("high", "the database and its data"),
    "google_sql_database": ("high", "the database and its data"),
    "google_storage_bucket": ("high", "the bucket and every object in it"),
    "google_bigquery_dataset": ("high", "the dataset and its tables"),
    "google_bigquery_table": ("high", "the table and its data"),
    "google_spanner_instance": ("high", "the instance and its databases"),
    "google_spanner_database": ("high", "the database and its data"),
    "google_bigtable_instance": ("high", "the instance and its tables"),
    "google_firestore_database": ("high", "the database and its documents"),
    "google_alloydb_cluster": ("high", "the cluster and its data"),
    "google_alloydb_instance": ("high", "the instance and its data"),
    "google_redis_instance": ("high", "the cache contents (and the instance's address)"),
    "google_filestore_instance": ("high", "the file share and its files"),
    "google_compute_disk": ("high", "the disk and its data"),
    "google_compute_region_disk": ("high", "the disk and its data"),
    "google_container_cluster": ("high", "the cluster and the workloads on it"),
    "google_kms_crypto_key": (
        "high",
        "every version of the key, so data encrypted with it becomes unreadable",
    ),
    "google_secret_manager_secret": ("high", "the secret and all its versions"),
    "google_compute_address": (
        "medium",
        "the reserved IP address (anything that points at it stops working)",
    ),
    "google_compute_global_address": (
        "medium",
        "the reserved IP address (anything that points at it stops working)",
    ),
    "google_dns_managed_zone": ("medium", "the zone and its records"),
    "aws_db_instance": ("high", "the database and its data"),
    "aws_rds_cluster": ("high", "the cluster and its data"),
    "aws_s3_bucket": ("high", "the bucket and every object in it"),
    "aws_ebs_volume": ("high", "the volume and its data"),
    "aws_efs_file_system": ("high", "the file system and its files"),
    "aws_dynamodb_table": ("high", "the table and its items"),
    "aws_kms_key": ("high", "the key, so data encrypted with it becomes unreadable"),
    "aws_secretsmanager_secret": ("high", "the secret and all its versions"),
    "aws_redshift_cluster": ("high", "the cluster and its data"),
    "aws_opensearch_domain": ("high", "the domain and its indices"),
    "aws_elasticache_replication_group": ("high", "the cache contents"),
    "aws_eip": ("medium", "the Elastic IP (anything that points at it stops working)"),
    "aws_route53_zone": ("medium", "the zone and its records"),
    "azurerm_mssql_database": ("high", "the database and its data"),
    "azurerm_postgresql_flexible_server": ("high", "the server and its databases"),
    "azurerm_storage_account": ("high", "the account and everything stored in it"),
    "azurerm_managed_disk": ("high", "the disk and its data"),
    "azurerm_key_vault": ("high", "the vault and its keys and secrets"),
    "azurerm_cosmosdb_account": ("high", "the account and its data"),
}


@rule(
    "data-loss",
    "high / medium",
    "A resource that holds data (databases, buckets, disks, keys, secrets, reserved IPs, DNS zones) is destroyed or replaced.",
    f"{len(STATEFUL)} types in Google Cloud, AWS and Azure; more with `stateful_types` in the config",
)
def data_loss(ch: Change, cfg: Config) -> list[Finding]:
    if ch.mode != "managed" or ch.kind not in ("delete", "replace"):
        return []
    if ch.type in STATEFUL:
        severity, lost = STATEFUL[ch.type]
    elif ch.type in cfg.stateful_types:
        severity, lost = "high", "whatever it holds"
    else:
        return []
    if ch.kind == "delete":
        advice = (
            "Check for a backup or an export first. If the destroy is not intended, find out why the resource "
            "left the plan: a removed block, a renamed resource, a changed count or for_each, a missing variable."
        )
        title = "will be destroyed"
        detail = f"Destroying it removes {lost}."
        if ch.why:
            detail += f" Reason: {ch.why}."
    else:
        advice = (
            "Check for a backup or an export first. If the replacement is not intended, find the argument that "
            "forces it (the plan marks it) and keep its old value."
        )
        title = "will be destroyed and created again"
        order = (
            "The new one is created first and the old one destroyed after"
            if ch.create_before_destroy
            else "The old one is destroyed and a new one is created"
        )
        forced = f", forced by {', '.join(ch.replace_paths)}" if ch.replace_paths else ""
        detail = f"{order}{forced}. Nothing is copied across: getting {lost} back needs a backup."
    return [
        _f(
            "data-loss",
            severity,
            ch,
            title,
            detail,
            advice,
        )
    ]


@plan_rule(
    "mass-destroy",
    "medium",
    "Many resources are destroyed or replaced in one plan (10 by default; `mass_destroy` in the config).",
    "the whole plan",
)
def mass_destroy(plan: Plan, cfg: Config) -> list[Finding]:
    c = plan.counts()
    n = c.destroy + c.replace
    if n < cfg.mass_destroy:
        return []
    return [
        Finding(
            "mass-destroy",
            "medium",
            "(plan)",
            f"{n} resources will be destroyed",
            f"{c.destroy} will be destroyed and {c.replace} replaced; the threshold is {cfg.mass_destroy}.",
            "A change that large usually means a wrong workspace, a renamed module, or a variable that went missing. Check before applying.",
        )
    ]


PROTECTED = {
    "google_sql_database_instance",
    "google_container_cluster",
    "google_bigquery_table",
    "aws_db_instance",
    "aws_rds_cluster",
}
PROTECTION_ATTRS = ("deletion_protection", "enable_deletion_protection", "deletion_protection_enabled")


@rule(
    "protection-removed",
    "medium / low",
    "Deletion protection is switched off on an existing resource, or a database or cluster is created without it.",
    "google_sql_database_instance, google_container_cluster, google_bigquery_table, aws_db_instance, aws_rds_cluster, aws_lb, aws_dynamodb_table",
)
def protection_removed(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    for attr in PROTECTION_ATTRS:
        after = ch.after.get(attr)
        if after is not False:
            continue
        if ch.kind == "update" and ch.before_values(attr) == [True]:
            return [
                _f(
                    "protection-removed",
                    "medium",
                    ch,
                    "deletion protection is being switched off",
                    "This is often the first step before a destroy: the guard that stops an accidental delete is removed.",
                    "Keep it on, and switch it off in a separate change right before an intended destroy.",
                    f"{attr}: true → false",
                )
            ]
        if ch.kind in ("create", "replace") and ch.type in PROTECTED:
            return [
                _f(
                    "protection-removed",
                    "low",
                    ch,
                    "created without deletion protection",
                    "Nothing stops a later plan or a console click from deleting it.",
                    f"Set {attr} = true.",
                    f"{attr} = false",
                )
            ]
    return []


SNAPSHOT_TYPES = {"aws_db_instance", "aws_rds_cluster", "aws_redshift_cluster"}


@rule(
    "no-final-snapshot",
    "high",
    "A database is destroyed with skip_final_snapshot = true, so nothing is kept.",
    "aws_db_instance, aws_rds_cluster, aws_redshift_cluster",
)
def no_final_snapshot(ch: Change, cfg: Config) -> list[Finding]:
    if ch.mode != "managed" or ch.kind not in ("delete", "replace") or ch.type not in SNAPSHOT_TYPES:
        return []
    if True in ch.before_values("skip_final_snapshot"):
        return [
            _f(
                "no-final-snapshot",
                "high",
                ch,
                "destroyed without a final snapshot",
                "skip_final_snapshot is true, so the data is gone the moment the destroy finishes.",
                "Take a manual snapshot first, or set skip_final_snapshot = false and apply that before the destroy.",
                "skip_final_snapshot = true",
            )
        ]
    return []


ENCRYPTION = {
    "aws_ebs_volume": "encrypted",
    "aws_efs_file_system": "encrypted",
    "aws_redshift_cluster": "encrypted",
    "aws_db_instance": "storage_encrypted",
    "aws_rds_cluster": "storage_encrypted",
}


@rule(
    "unencrypted",
    "medium",
    "Storage that is explicitly created with encryption switched off.",
    "aws_ebs_volume, aws_efs_file_system, aws_redshift_cluster, aws_db_instance, aws_rds_cluster",
)
def unencrypted(ch: Change, cfg: Config) -> list[Finding]:
    attr = ENCRYPTION.get(ch.type)
    if not attr or not _planned(ch) or ch.after.get(attr) is not False:
        return []
    return [
        _f(
            "unencrypted",
            "medium",
            ch,
            "encryption at rest is off",
            f"{attr} is false, so the data is stored unencrypted (and it usually cannot be turned on later without a copy).",
            f"Set {attr} = true.",
            f"{attr} = false",
        )
    ]


@rule(
    "backups-off",
    "medium",
    "Automated backups are switched off for a database.",
    "google_sql_database_instance, aws_db_instance, aws_rds_cluster",
)
def backups_off(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    off = (
        ch.type == "google_sql_database_instance"
        and False in ch.after_values("settings", "backup_configuration", "enabled")
    ) or (ch.type in ("aws_db_instance", "aws_rds_cluster") and ch.after.get("backup_retention_period") == 0)
    if not off:
        return []
    evidence = (
        "settings.backup_configuration.enabled = false"
        if ch.type == "google_sql_database_instance"
        else "backup_retention_period = 0"
    )
    return [
        _f(
            "backups-off",
            "medium",
            ch,
            "automated backups are off",
            "Without backups there is nothing to restore if the data is damaged or deleted.",
            "Turn backups on (and test a restore once).",
            evidence,
        )
    ]


@rule(
    "long-lived-credential",
    "medium",
    "A service-account key or an access key is created: a credential that does not expire.",
    "google_service_account_key, aws_iam_access_key",
)
def long_lived_credential(ch: Change, cfg: Config) -> list[Finding]:
    if ch.type not in ("google_service_account_key", "aws_iam_access_key") or ch.mode != "managed":
        return []
    if ch.kind not in ("create", "replace"):
        return []
    return [
        _f(
            "long-lived-credential",
            "medium",
            ch,
            "creates a key that never expires",
            "The key ends up in the Terraform state and in whatever uses it; it stays valid until someone deletes it.",
            "Prefer workload identity (Google Cloud) or roles (AWS); if a key is unavoidable, rotate it on a schedule.",
        )
    ]


@rule(
    "vm-broad-access",
    "medium",
    "A VM whose service account has the cloud-platform scope: every API, limited only by the account's IAM roles.",
    "google_compute_instance, google_compute_instance_template",
)
def vm_broad_access(ch: Change, cfg: Config) -> list[Finding]:
    if ch.type not in ("google_compute_instance", "google_compute_instance_template") or not _planned(ch):
        return []
    scopes = [s for s in ch.after_values("service_account", "scopes") if isinstance(s, str)]
    if not any(s.endswith("/cloud-platform") or s == "cloud-platform" for s in scopes):
        return []
    return [
        _f(
            "vm-broad-access",
            "medium",
            ch,
            "service account has the cloud-platform scope",
            "Anything running on the VM, or anyone who gets code execution on it, can call every Google API the service account has roles for.",
            "Give the VM its own service account with only the roles it needs; the scope can stay as long as the roles are narrow.",
            _ev(ch, "scopes", "service_account", "scopes", many=True),
        )
    ]


@rule(
    "vm-public-ip",
    "low",
    "A VM gets a public IP address.",
    "google_compute_instance, aws_instance",
)
def vm_public_ip(ch: Change, cfg: Config) -> list[Finding]:
    if not _planned(ch):
        return []
    public = (
        ch.type == "google_compute_instance" and bool(ch.after_values("network_interface", "access_config"))
    ) or (ch.type == "aws_instance" and ch.after.get("associate_public_ip_address") is True)
    if not public:
        return []
    return [
        _f(
            "vm-public-ip",
            "low",
            ch,
            "gets a public IP address",
            "It can be reached from the internet as far as the firewall allows.",
            "Use a load balancer, or an identity-aware proxy for admin access, and drop the public address.",
        )
    ]


def check_change(ch: Change, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for fn in _CHANGE_RULES.values():
        out.extend(fn(ch, cfg))
    return out


def check_plan(plan: Plan, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for fn in _PLAN_RULES.values():
        out.extend(fn(plan, cfg))
    return out


def rules_markdown() -> str:
    lines = ["| Rule | Severity | What it catches | Resources |", "|---|---|---|---|"]
    for r in sorted(RULES, key=lambda r: r.id):
        lines.append(f"| `{r.id}` | {r.severity} | {r.summary} | {r.covers} |")
    return "\n".join(lines)
