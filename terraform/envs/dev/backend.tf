terraform {
  backend "s3" {
    bucket       = "medium-example-terraform-state-dev"
    key          = "bedrock-guard/dev/terraform.tfstate"
    region       = "eu-west-1"
    encrypt      = true
    use_lockfile = true
  }
}
