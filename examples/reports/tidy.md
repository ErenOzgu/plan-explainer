## Terraform plan: 2 to add, 1 to change

This plan creates 2 resources and changes 1. The rules raised no findings. They cover a fixed list of risks (`plan-explainer rules`), so that is not the same as a review.

<sub>Summary written by the rules.</sub>

### Findings

None. The rules cover a fixed list of risks (`plan-explainer rules`); this is not a review.

### Changes

| Action | Resource | Detail |
|---|---|---|
| change | `google_compute_instance.worker` | labels.env |
| add | `google_compute_firewall.web` |  |
| add | `google_storage_bucket.reports` |  |

<details><summary>Argument changes</summary>

`google_compute_instance.worker`

- `labels.env: (none) → "prod"`

</details>

<sub>plan-explainer 0.1.0 · Terraform/OpenTofu 1.9.8 · plan format 1.2</sub>
