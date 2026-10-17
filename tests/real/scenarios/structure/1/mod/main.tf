variable "name" { type = string }
variable "secret" {
  type      = string
  sensitive = true
}
resource "terraform_data" "inner" {
  input = { name = var.name, token = var.secret }
}
