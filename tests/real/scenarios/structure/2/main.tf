variable "gen" { default = "2" }
resource "terraform_data" "cbd" {
  triggers_replace = [var.gen]
  lifecycle { create_before_destroy = true }
}
resource "terraform_data" "counted" {
  count = 2
  input = "n${count.index}-${var.gen}"
}
resource "terraform_data" "keyed" {
  for_each = toset(["a"])
  input    = each.key
}
module "m" {
  source = "./mod"
  name   = "web"
  secret = "hunter2-rotated"
}
