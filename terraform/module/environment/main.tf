module "network" {
  source = "../network"

  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  bastion_ingress    = var.bastion_ingress
  cidr               = "10.0.0.0/16"
  name               = var.name
}
