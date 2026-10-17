"""Writes the example plans in this directory.

They are assembled by hand in the exact shape of `terraform show -json` (format 1.2), because planning
real Google Cloud resources needs the provider and a project. CI also plans real configurations with the
real provider (examples/terraform) and checks that the findings are the ones expected there.

    python examples/make_plans.py
"""

from __future__ import annotations

import json
from pathlib import Path

GOOGLE = "registry.terraform.io/hashicorp/google"
HERE = Path(__file__).parent


def rc(rtype, name, actions, before=None, after=None, unknown=None, **extra):
    change = {
        "actions": actions,
        "before": before,
        "after": after,
        "after_unknown": unknown or {},
        "before_sensitive": extra.pop("before_sensitive", False),
        "after_sensitive": extra.pop("after_sensitive", {}),
    }
    if "replace_paths" in extra:
        change["replace_paths"] = extra.pop("replace_paths")
    out = {
        "address": f"{rtype}.{name}",
        "mode": "managed",
        "type": rtype,
        "name": name,
        "provider_name": GOOGLE,
        "change": change,
    }
    if "reason" in extra:
        out["action_reason"] = extra.pop("reason")
    return out


def plan(*changes):
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.8",
        "planned_values": {"root_module": {}},
        "resource_changes": sorted(changes, key=lambda c: c["address"]),
        "output_changes": {},
        "configuration": {},
        "errored": False,
    }


def sql(region, backups):
    return {
        "name": "orders",
        "database_version": "POSTGRES_15",
        "region": region,
        "deletion_protection": False,
        "settings": [
            {
                "tier": "db-custom-2-7680",
                "backup_configuration": [{"enabled": backups}],
                "ip_configuration": [{"ipv4_enabled": False, "authorized_networks": []}],
            }
        ],
    }


def vm(machine_type):
    return {
        "name": "app-1",
        "machine_type": machine_type,
        "zone": "europe-west3-b",
        "network_interface": [{"network": "default", "access_config": [{"nat_ip": "34.89.0.10"}]}],
        "service_account": [
            {
                "email": "app@shop-prod.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            }
        ],
    }


def bucket(ubla, versioning):
    return {
        "name": "shop-uploads",
        "location": "EU",
        "uniform_bucket_level_access": ubla,
        "versioning": [{"enabled": versioning}],
    }


def webshop():
    return plan(
        rc(
            "google_compute_firewall",
            "debug_ssh",
            ["create"],
            after={
                "name": "debug-ssh",
                "network": "default",
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["22"]}],
            },
        ),
        rc(
            "google_compute_firewall",
            "web",
            ["create"],
            after={
                "name": "web",
                "network": "default",
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["80", "443"]}],
            },
        ),
        rc(
            "google_project_iam_member",
            "ci_deployer",
            ["create"],
            after={
                "project": "shop-prod",
                "role": "roles/owner",
                "member": "serviceAccount:ci-deployer@shop-prod.iam.gserviceaccount.com",
            },
        ),
        rc(
            "google_service_account_key",
            "ci_deployer",
            ["create"],
            after={"service_account_id": "ci-deployer"},
            unknown={"private_key": True, "id": True},
            after_sensitive={"private_key": True},
        ),
        rc(
            "google_sql_database_instance",
            "orders",
            ["delete", "create"],
            before=sql("europe-west1", True),
            after=sql("europe-west3", False),
            unknown={"id": True, "connection_name": True},
            replace_paths=[["region"]],
            reason="replace_because_cannot_update",
        ),
        rc(
            "google_compute_instance",
            "app",
            ["update"],
            before=vm("e2-small"),
            after=vm("e2-medium"),
        ),
        rc(
            "google_storage_bucket",
            "uploads",
            ["update"],
            before=bucket(True, True),
            after=bucket(False, False),
        ),
        rc(
            "google_storage_bucket_iam_member",
            "assets_public",
            ["create"],
            after={"bucket": "shop-assets", "role": "roles/storage.objectViewer", "member": "allUsers"},
        ),
        rc(
            "google_compute_address",
            "app_ip",
            ["delete"],
            before={"name": "app-ip", "address": "34.89.0.10", "region": "europe-west3"},
            reason="delete_because_no_resource_config",
        ),
        rc(
            "google_compute_disk",
            "old_data",
            ["delete"],
            before={"name": "old-data", "size": 500, "type": "pd-ssd", "zone": "europe-west3-b"},
            reason="delete_because_no_resource_config",
        ),
        rc(
            "google_dns_record_set",
            "www",
            ["update"],
            before={"name": "www.shop.example.", "type": "A", "ttl": 300, "rrdatas": ["34.89.0.10"]},
            after={"name": "www.shop.example.", "type": "A", "ttl": 300, "rrdatas": ["34.89.0.20"]},
        ),
        rc(
            "google_logging_project_sink",
            "audit",
            ["create"],
            after={
                "name": "audit",
                "destination": "storage.googleapis.com/shop-audit-logs",
                "filter": "logName:cloudaudit.googleapis.com",
            },
        ),
        rc(
            "google_secret_manager_secret_version",
            "db_password",
            ["update"],
            before={"secret": "projects/1/secrets/db", "secret_data": "old-value", "enabled": True},
            after={"secret": "projects/1/secrets/db", "secret_data": "new-value", "enabled": True},
            before_sensitive={"secret_data": True},
            after_sensitive={"secret_data": True},
        ),
    )


def tidy():
    return plan(
        rc(
            "google_compute_firewall",
            "web",
            ["create"],
            after={
                "name": "web",
                "network": "default",
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["443"]}],
            },
        ),
        rc(
            "google_storage_bucket",
            "reports",
            ["create"],
            after=bucket(True, True) | {"name": "shop-reports"},
        ),
        rc(
            "google_compute_instance",
            "worker",
            ["update"],
            before={"name": "worker", "labels": {"team": "shop"}, "machine_type": "e2-small"},
            after={"name": "worker", "labels": {"team": "shop", "env": "prod"}, "machine_type": "e2-small"},
        ),
    )


if __name__ == "__main__":
    for name, doc in (("webshop", webshop()), ("tidy", tidy())):
        (HERE / "plans" / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
        print("wrote", f"plans/{name}.json")
