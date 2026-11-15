provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "bedrock-guard"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}
