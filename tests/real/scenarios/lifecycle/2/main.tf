resource "terraform_data" "keep" {
  input = "v1"
}
resource "terraform_data" "change_me" {
  input = "after"
}
resource "terraform_data" "replace_me" {
  triggers_replace = ["b"]
}
resource "terraform_data" "brand_new" {
  input = "hello"
}
output "new_output" {
  value = "x"
}
