package terraform

import rego.v1

# Helper to get all resource changes
resource_changes := input.resource_changes

# Helper to get resources by type
resources_by_type(type) := [r | r := resource_changes[_]; r.type == type]


# ==============================================================================
# INSTANCE TYPE RESTRICTIONS
# ==============================================================================

# Define allowed instance types
allowed_instance_types := ["t3.micro", "t3.small"]

# Deny instances with disallowed instance types
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type
    not instance_type in allowed_instance_types
    msg := sprintf("Instance type for '%s' is '%s', but must be one of %v", [resource.address, instance_type, allowed_instance_types])
}
# ==============================================================================
# CRITICAL SECURITY POLICIES
# ==============================================================================

# Deny RDS instances without encryption
deny contains msg if {
    some resource in resources_by_type("aws_db_instance")
    resource.change.after.storage_encrypted != true
    msg := sprintf("🚨 CRITICAL: RDS Instance '%s' must have storage encryption enabled", [resource.address])
}

# Deny publicly accessible RDS instances
deny contains msg if {
    some resource in resources_by_type("aws_db_instance")
    resource.change.after.publicly_accessible == true
    msg := sprintf("🚨 CRITICAL: RDS Instance '%s' must not be publicly accessible", [resource.address])
}

# Deny RDS instances with insufficient backup retention
deny contains msg if {
    some resource in resources_by_type("aws_db_instance")
    resource.change.after.backup_retention_period
    resource.change.after.backup_retention_period < 7
    msg := sprintf("🔒 SECURITY: RDS Instance '%s' must have backup retention >= 7 days (current: %d)", [resource.address, resource.change.after.backup_retention_period])
}

# Deny RDS instances without deletion protection in production
deny contains msg if {
    some resource in resources_by_type("aws_db_instance")
    resource.change.after.deletion_protection != true
    not contains(resource.address, "staging")
    not contains(resource.address, "dev")
    not contains(resource.address, "test")
    msg := sprintf("🔒 SECURITY: Production RDS Instance '%s' must have deletion protection enabled", [resource.address])
}

# Deny EC2 instances without IMDSv2
deny contains msg if {
    some resource in resources_by_type("aws_instance")
    not resource.change.after.metadata_options
    msg := sprintf("🚨 CRITICAL: EC2 Instance '%s' must configure IMDSv2 metadata options", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_instance")
    resource.change.after.metadata_options
    resource.change.after.metadata_options.http_tokens != "required"
    msg := sprintf("🚨 CRITICAL: EC2 Instance '%s' must require IMDSv2 (http_tokens = 'required')", [resource.address])
}

# Deny launch templates without IMDSv2
#deny contains msg if {
#   some resource in resources_by_type("aws_launch_template")
#    not resource.change.after.metadata_options
#    msg := sprintf("🚨 CRITICAL: Launch Template '%s' must configure IMDSv2 metadata options", [resource.address])
#}

# Deny unrestricted SSH access
deny contains msg if {
    some resource in resources_by_type("aws_vpc_security_group_ingress_rule")
    resource.change.after.from_port == 22
    resource.change.after.cidr_ipv4 == "0.0.0.0/0"
    msg := sprintf("🚨 CRITICAL: Security Group Rule '%s' allows unrestricted SSH access from 0.0.0.0/0", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_security_group_rule")
    resource.change.after.type == "ingress"
    resource.change.after.from_port == 22
    resource.change.after.cidr_blocks
    "0.0.0.0/0" in resource.change.after.cidr_blocks
    msg := sprintf("🚨 CRITICAL: Security Group Rule '%s' allows unrestricted SSH access from 0.0.0.0/0", [resource.address])
}

# Deny security groups allowing database ports from anywhere
database_ports := [3306, 5432, 1433, 27017, 6379]

deny contains msg if {
    some resource in resources_by_type("aws_vpc_security_group_ingress_rule")
    some port in database_ports
    resource.change.after.from_port == port
    resource.change.after.cidr_ipv4 == "0.0.0.0/0"
    msg := sprintf("🚨 CRITICAL: Security Group Rule '%s' allows database port %d from 0.0.0.0/0", [resource.address, port])
}

deny contains msg if {
    some resource in resources_by_type("aws_security_group_rule")
    resource.change.after.type == "ingress"
    some port in database_ports
    resource.change.after.from_port == port
    resource.change.after.cidr_blocks
    "0.0.0.0/0" in resource.change.after.cidr_blocks
    msg := sprintf("🚨 CRITICAL: Security Group Rule '%s' allows database port %d from 0.0.0.0/0", [resource.address, port])
}

# Deny CloudFront distributions without HTTPS enforcement
deny contains msg if {
    some resource in resources_by_type("aws_cloudfront_distribution")
    resource.change.after.default_cache_behavior.viewer_protocol_policy != "redirect-to-https"
    resource.change.after.default_cache_behavior.viewer_protocol_policy != "https-only"
    msg := sprintf("🔒 SECURITY: CloudFront Distribution '%s' must enforce HTTPS", [resource.address])
}

# Deny SSM parameters with sensitive names that aren't SecureString
deny contains msg if {
    some resource in resources_by_type("aws_ssm_parameter")
    contains(lower(resource.change.after.name), "password")
    resource.change.after.type != "SecureString"
    msg := sprintf("🚨 CRITICAL: SSM Parameter '%s' contains 'password' and must be type SecureString", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_ssm_parameter")
    contains(lower(resource.change.after.name), "secret")
    resource.change.after.type != "SecureString"
    msg := sprintf("🚨 CRITICAL: SSM Parameter '%s' contains 'secret' and must be type SecureString", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_ssm_parameter")
    contains(lower(resource.change.after.name), "key")
    resource.change.after.type != "SecureString"
    msg := sprintf("🚨 CRITICAL: SSM Parameter '%s' contains 'key' and must be type SecureString", [resource.address])
}

# ==============================================================================
# HIGH PRIORITY POLICIES
# ==============================================================================

# Deny ECS clusters without Container Insights
deny contains msg if {
    some resource in resources_by_type("aws_ecs_cluster")
    not resource.change.after.setting
    msg := sprintf("🔒 SECURITY: ECS Cluster '%s' must enable Container Insights", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_ecs_cluster")
    resource.change.after.setting
    some setting in resource.change.after.setting
    setting.name == "containerInsights"
    setting.value != "enabled"
    msg := sprintf("🔒 SECURITY: ECS Cluster '%s' must have Container Insights enabled", [resource.address])
}

# Deny S3 buckets without encryption
deny contains msg if {
    some resource in resources_by_type("aws_s3_bucket")
    not resource.change.after.server_side_encryption_configuration
    msg := sprintf("🔒 SECURITY: S3 Bucket '%s' must have encryption enabled", [resource.address])
}

# Deny public S3 buckets
deny contains msg if {
    some resource in resources_by_type("aws_s3_bucket_public_access_block")
    resource.change.after.block_public_acls != true
    msg := sprintf("🚨 CRITICAL: S3 Bucket '%s' must block public ACLs", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_s3_bucket_public_access_block")
    resource.change.after.block_public_policy != true
    msg := sprintf("🚨 CRITICAL: S3 Bucket '%s' must block public policies", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_s3_bucket_public_access_block")
    resource.change.after.ignore_public_acls != true
    msg := sprintf("🚨 CRITICAL: S3 Bucket '%s' must ignore public ACLs", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_s3_bucket_public_access_block")
    resource.change.after.restrict_public_buckets != true
    msg := sprintf("🚨 CRITICAL: S3 Bucket '%s' must restrict public bucket access", [resource.address])
}

# Deny load balancers without deletion protection in production
deny contains msg if {
    some resource in resources_by_type("aws_lb")
    resource.change.after.enable_deletion_protection != true
    not contains(resource.address, "staging")
    not contains(resource.address, "dev")
    not contains(resource.address, "test")
    msg := sprintf("🔒 SECURITY: Production Load Balancer '%s' must have deletion protection enabled", [resource.address])
}

# Deny VPCs without DNS support
deny contains msg if {
    some resource in resources_by_type("aws_vpc")
    resource.change.after.enable_dns_support != true
    msg := sprintf("🔒 SECURITY: VPC '%s' must have DNS support enabled", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_vpc")
    resource.change.after.enable_dns_hostnames != true
    msg := sprintf("🔒 SECURITY: VPC '%s' must have DNS hostnames enabled", [resource.address])
}

# Deny IAM policies with wildcard actions
deny contains msg if {
    some resource in resources_by_type("aws_iam_policy")
    resource.change.after.policy
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    statement.Action == "*"
    msg := sprintf("🚨 CRITICAL: IAM Policy '%s' allows wildcard actions (*)", [resource.address])
}

deny contains msg if {
    some resource in resources_by_type("aws_iam_policy")
    resource.change.after.policy
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    is_array(statement.Action)
    some action in statement.Action
    action == "*"
    msg := sprintf("🚨 CRITICAL: IAM Policy '%s' allows wildcard actions (*)", [resource.address])
}

# Deny overly permissive IAM assume role policies
deny contains msg if {
    some resource in resources_by_type("aws_iam_role")
    resource.change.after.assume_role_policy
    policy := json.unmarshal(resource.change.after.assume_role_policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    statement.Principal == "*"
    msg := sprintf("🚨 CRITICAL: IAM Role '%s' has overly permissive assume role policy (Principal: *)", [resource.address])
}

# Deny RDS without Multi-AZ in production
deny contains msg if {
    some resource in resources_by_type("aws_db_instance")
    resource.change.after.multi_az != true
    not contains(resource.address, "staging")
    not contains(resource.address, "dev")
    not contains(resource.address, "test")
    msg := sprintf("🔒 SECURITY: Production RDS Instance '%s' should use Multi-AZ for high availability", [resource.address])
}

# Deny Auto Scaling Groups with min_size of 0
deny contains msg if {
    some resource in resources_by_type("aws_autoscaling_group")
    resource.change.after.min_size < 1
    msg := sprintf("🔒 SECURITY: Auto Scaling Group '%s' must have min_size >= 1 for availability", [resource.address])
}