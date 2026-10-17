# The same kinds of resources, written so that no rule has anything to say.

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

resource "google_compute_firewall" "web" {
  name          = "web"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "ssh_from_iap" {
  name          = "ssh-from-iap"
  network       = "default"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_project_iam_member" "reviewer" {
  project = "demo-project"
  role    = "roles/viewer"
  member  = "user:reviewer@example.com"
}

resource "google_storage_bucket" "reports" {
  name                        = "demo-project-reports"
  location                    = "EU"
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }
}

resource "google_service_account" "worker" {
  account_id = "worker"
}

resource "google_compute_instance" "worker" {
  name         = "worker"
  machine_type = "e2-small"
  zone         = "europe-west3-b"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
  }
  service_account {
    email  = google_service_account.worker.email
    scopes = ["logging-write", "monitoring-write"]
  }
}
