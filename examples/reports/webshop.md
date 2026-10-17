## Terraform plan: 6 to add, 4 to change, 1 to replace, 2 to destroy

This plan creates 6 resources, changes 4, replaces 1 and destroys 2. The rules raised 12 findings: 5 high, 4 medium and 3 low. Start with `google_compute_disk.old_data` (data-loss), `google_compute_firewall.debug_ssh` (open-ingress), `google_project_iam_member.ci_deployer` (broad-role), `google_sql_database_instance.orders` (data-loss) and `google_storage_bucket_iam_member.assets_public` (public-policy).

<sub>Summary written by the rules.</sub>

### Look at first

| Severity | Rule | Resource | Finding |
|---|---|---|---|
| HIGH | data-loss | `google_compute_disk.old_data` | will be destroyed |
| HIGH | open-ingress | `google_compute_firewall.debug_ssh` | SSH (22) open to the internet |
| HIGH | broad-role | `google_project_iam_member.ci_deployer` | roles/owner on a whole project |
| HIGH | data-loss | `google_sql_database_instance.orders` | will be destroyed and created again |
| HIGH | public-policy | `google_storage_bucket_iam_member.assets_public` | roles/storage.objectViewer granted to allUsers |
| MEDIUM | data-loss | `google_compute_address.app_ip` | will be destroyed |
| MEDIUM | vm-broad-access | `google_compute_instance.app` | service account has the cloud-platform scope |
| MEDIUM | long-lived-credential | `google_service_account_key.ci_deployer` | creates a key that never expires |
| MEDIUM | backups-off | `google_sql_database_instance.orders` | automated backups are off |
| LOW | vm-public-ip | `google_compute_instance.app` | gets a public IP address |
| LOW | protection-removed | `google_sql_database_instance.orders` | created without deletion protection |
| LOW | public-storage | `google_storage_bucket.uploads` | uniform bucket-level access is off |

**HIGH · data-loss** · `google_compute_disk.old_data` · will be destroyed

Destroying it removes the disk and its data. Reason: it is no longer in the configuration.

What to do: Check for a backup or an export first. If the destroy is not intended, find out why the resource left the plan: a removed block, a renamed resource, a changed count or for_each, a missing variable.

**HIGH · open-ingress** · `google_compute_firewall.debug_ssh` · SSH (22) open to the internet

Allows inbound traffic from 0.0.0.0/0 to: SSH (22).

Evidence: `source_ranges = ["0.0.0.0/0"]`; `allow = [{"ports": ["22"], "protocol": "tcp"}]`

What to do: Restrict the source range to the networks that need access (a VPN, an office range, an identity-aware proxy).

**HIGH · broad-role** · `google_project_iam_member.ci_deployer` · roles/owner on a whole project

serviceAccount:ci-deployer@shop-prod.iam.gserviceaccount.com gets full control of everything in the scope.

Evidence: `role = "roles/owner"`; `member = "serviceAccount:ci-deployer@shop-prod.iam.gserviceaccount.com"`

What to do: Use a narrower predefined or custom role, or grant it on the one resource that needs it.

**HIGH · data-loss** · `google_sql_database_instance.orders` · will be destroyed and created again

The old one is destroyed and a new one is created, forced by region. Nothing is copied across: getting the database and its data back needs a backup.

What to do: Check for a backup or an export first. If the replacement is not intended, find the argument that forces it (the plan marks it) and keep its old value.

**HIGH · public-policy** · `google_storage_bucket_iam_member.assets_public` · roles/storage.objectViewer granted to allUsers

Gives everyone on the internet the role roles/storage.objectViewer.

Evidence: `role = "roles/storage.objectViewer"`; `member = "allUsers"`

What to do: Grant the role to specific identities, or serve public content through a load balancer or CDN.

**MEDIUM · data-loss** · `google_compute_address.app_ip` · will be destroyed

Destroying it removes the reserved IP address (anything that points at it stops working). Reason: it is no longer in the configuration.

What to do: Check for a backup or an export first. If the destroy is not intended, find out why the resource left the plan: a removed block, a renamed resource, a changed count or for_each, a missing variable.

**MEDIUM · vm-broad-access** · `google_compute_instance.app` · service account has the cloud-platform scope

Anything running on the VM, or anyone who gets code execution on it, can call every Google API the service account has roles for.

Evidence: `scopes = ["https://www.googleapis.com/auth/cloud-platform"]`

What to do: Give the VM its own service account with only the roles it needs; the scope can stay as long as the roles are narrow.

**MEDIUM · long-lived-credential** · `google_service_account_key.ci_deployer` · creates a key that never expires

The key ends up in the Terraform state and in whatever uses it; it stays valid until someone deletes it.

What to do: Prefer workload identity (Google Cloud) or roles (AWS); if a key is unavoidable, rotate it on a schedule.

**MEDIUM · backups-off** · `google_sql_database_instance.orders` · automated backups are off

Without backups there is nothing to restore if the data is damaged or deleted.

Evidence: `settings.backup_configuration.enabled = false`

What to do: Turn backups on (and test a restore once).

**LOW · vm-public-ip** · `google_compute_instance.app` · gets a public IP address

It can be reached from the internet as far as the firewall allows.

What to do: Use a load balancer, or an identity-aware proxy for admin access, and drop the public address.

**LOW · protection-removed** · `google_sql_database_instance.orders` · created without deletion protection

Nothing stops a later plan or a console click from deleting it.

Evidence: `deletion_protection = false`

What to do: Set deletion_protection = true.

**LOW · public-storage** · `google_storage_bucket.uploads` · uniform bucket-level access is off

Individual objects can be made public with their own ACLs, outside the bucket's IAM policy.

Evidence: `uniform_bucket_level_access = false`

What to do: Set uniform_bucket_level_access = true.

### Changes

| Action | Resource | Detail |
|---|---|---|
| replace | `google_sql_database_instance.orders` | forced by region |
| destroy | `google_compute_address.app_ip` | it is no longer in the configuration |
| destroy | `google_compute_disk.old_data` | it is no longer in the configuration |
| change | `google_compute_instance.app` | machine_type |
| change | `google_dns_record_set.www` | rrdatas[0] |
| change | `google_secret_manager_secret_version.db_password` | secret_data |
| change | `google_storage_bucket.uploads` | uniform_bucket_level_access, versioning[0].enabled |
| add | `google_compute_firewall.debug_ssh` |  |
| add | `google_compute_firewall.web` |  |
| add | `google_logging_project_sink.audit` |  |
| add | `google_project_iam_member.ci_deployer` |  |
| add | `google_service_account_key.ci_deployer` |  |
| add | `google_storage_bucket_iam_member.assets_public` |  |

<details><summary>Argument changes</summary>

`google_sql_database_instance.orders`

- `connection_name: (none) → (known after apply)`
- `region: "europe-west1" → "europe-west3"`
- `settings[0].backup_configuration[0].enabled: true → false`

`google_compute_instance.app`

- `machine_type: "e2-small" → "e2-medium"`

`google_dns_record_set.www`

- `rrdatas[0]: "34.89.0.10" → "34.89.0.20"`

`google_secret_manager_secret_version.db_password`

- `secret_data: (sensitive value changed)`

`google_storage_bucket.uploads`

- `uniform_bucket_level_access: true → false`
- `versioning[0].enabled: true → false`

</details>

<sub>plan-explainer 0.1.0 · Terraform/OpenTofu 1.9.8 · plan format 1.2</sub>
