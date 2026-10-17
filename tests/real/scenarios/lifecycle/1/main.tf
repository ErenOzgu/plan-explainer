resource "terraform_data" "keep" {
  input = "v1"
}
resource "terraform_data" "change_me" {
  input = "before"
}
resource "terraform_data" "replace_me" {
  triggers_replace = ["a"]
}
resource "terraform_data" "remove_me" {
  input = "bye"
}
