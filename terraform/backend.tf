terraform {
  backend "s3" {
    bucket = "tf-bucket-ecs-rds-pro"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}