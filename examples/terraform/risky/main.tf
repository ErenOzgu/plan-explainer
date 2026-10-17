# Plans real Google Cloud resources (nothing is created: CI only runs `terraform plan` with a dummy token).
# expected.txt lists the findings plan-explainer must report for this configuration, no more and no fewer.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.8.0"
    }
  }
}

provider "google" {
  project = "demo-project"
  region  = "europe-west3"
}

resource "google_compute_firewall" "debug_ssh" {
  name          = "debug-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "web" {
  name          = "web"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_project_iam_member" "ci_owner" {
  project = "demo-project"
  role    = "roles/owner"
  member  = "serviceAccount:ci@demo-project.iam.gserviceaccount.com"
}

resource "google_project_iam_binding" "viewers" {
  project = "demo-project"
  role    = "roles/viewer"
  members = ["user:reviewer@example.com"]
}

resource "google_storage_bucket" "assets" {
  name                        = "demo-project-assets"
  location                    = "EU"
  uniform_bucket_level_access = false
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_sql_database_instance" "orders" {
  name                = "orders"
  region              = "europe-west3"
  database_version    = "POSTGRES_15"
  deletion_protection = false
  settings {
    tier = "db-custom-2-7680"
    backup_configuration {
      enabled = false
    }
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "everyone"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_service_account" "app" {
  account_id = "app"
}

resource "google_service_account_key" "app" {
  service_account_id = google_service_account.app.name
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  zone         = "europe-west3-b"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
    access_config {}
  }
  service_account {
    scopes = ["cloud-platform"]
  }
}
