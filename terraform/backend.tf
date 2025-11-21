terraform {
  required_version = ">= 1.1.9"
  backend "s3" {
    bucket = "tf-bucket-ecs-rds-pro"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}