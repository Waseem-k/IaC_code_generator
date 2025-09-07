"""
Security rules configuration for different IaC platforms
"""
from typing import Dict, List
from src.models import SecurityRule

def get_terraform_rules() -> List[SecurityRule]:
    """Get Terraform security rules"""
    return [
        SecurityRule(
            rule_id="TF001",
            title="Public S3 Bucket",
            severity="high",
            patterns=[
                r'acl\s*=\s*["\']public-read["\']',
                r'acl\s*=\s*["\']public-read-write["\']',
                r'block_public_acls\s*=\s*false',
                r'ignore_public_acls\s*=\s*false',
                r'block_public_policy\s*=\s*false',
                r'restrict_public_buckets\s*=\s*false'
            ],
            description="S3 bucket is configured with public access, which may expose sensitive data to unauthorized users.",
            recommendation="Use private ACL and configure specific bucket policies. Enable S3 bucket public access block.",
            fix_example='acl = "private"\n\nbucket_public_access_block {\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}',
            category="Data Protection",
            cwe_id="CWE-200",
            cvss_score=7.5
        ),
        SecurityRule(
            rule_id="TF002",
            title="Unencrypted EBS Volume",
            severity="high",
            patterns=[
                r'resource\s+["\']aws_ebs_volume["\'][^}]*?(?!.*encrypted\s*=\s*true)[^}]*?}',
                r'ebs_block_device\s*{[^}]*?(?!.*encrypted\s*=\s*true)[^}]*?}'
            ],
            description="EBS volumes are not encrypted, potentially exposing sensitive data at rest.",
            recommendation="Enable encryption for all EBS volumes using AWS KMS keys to protect data at rest.",
            fix_example='encrypted = true\nkms_key_id = aws_kms_key.ebs.arn',
            category="Encryption",
            cwe_id="CWE-311",
            cvss_score=6.5
        ),
        SecurityRule(
            rule_id="TF003",
            title="Open Security Group - Inbound",
            severity="critical",
            patterns=[
                r'ingress\s*{[^}]*cidr_blocks\s*=\s*\[[^]]*["\']0\.0\.0\.0/0["\'][^]]*\]',
                r'from_port\s*=\s*0[^}]*to_port\s*=\s*65535[^}]*cidr_blocks\s*=\s*\[[^]]*["\']0\.0\.0\.0/0["\']',
                r'protocol\s*=\s*["\']tcp["\'][^}]*from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\[[^]]*["\']0\.0\.0\.0/0["\']'
            ],
            description="Security group allows unrestricted inbound access from the internet (0.0.0.0/0).",
            recommendation="Restrict inbound rules to specific IP ranges, security groups, or use AWS Systems Manager Session Manager for SSH access.",
            fix_example='cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12"]\n# Or use security group references\nsecurity_groups = [aws_security_group.app.id]',
            category="Network Security",
            cwe_id="CWE-16",
            cvss_score=9.0
        ),
        SecurityRule(
            rule_id="TF004",
            title="Unencrypted RDS Instance",
            severity="high",
            patterns=[
                r'resource\s+["\']aws_db_instance["\'][^}]*?(?!.*storage_encrypted\s*=\s*true)[^}]*?}'
            ],
            description="RDS database instance is not encrypted, potentially exposing sensitive data.",
            recommendation="Enable encryption for RDS instances and consider encryption in transit.",
            fix_example='storage_encrypted = true\nkms_key_id = aws_kms_key.rds.arn',
            category="Database Security",
            cwe_id="CWE-311",
            cvss_score=7.0
        ),
        SecurityRule(
            rule_id="TF005",
            title="IAM Policy with Wildcard Actions",
            severity="medium",
            patterns=[
                r'["\']Action["\']\s*[:=]\s*["\'][*]["\']',
                r'["\']Resource["\']\s*[:=]\s*["\'][*]["\']'
            ],
            description="IAM policy uses wildcard (*) for actions or resources, potentially granting excessive permissions.",
            recommendation="Follow the principle of least privilege by specifying exact actions and resources.",
            fix_example='"Action": ["s3:GetObject", "s3:PutObject"],\n"Resource": ["arn:aws:s3:::my-bucket/*"]',
            category="Access Control",
            cwe_id="CWE-269",
            cvss_score=5.5
        )
    ]

def get_cloudformation_rules() -> List[SecurityRule]:
    """Get CloudFormation security rules"""
    return [
        SecurityRule(
            rule_id="CF001",
            title="Public S3 Bucket Access",
            severity="high",
            patterns=[
                r'AccessControl["\']?\s*:\s*["\']?PublicRead',
                r'AccessControl["\']?\s*:\s*["\']?PublicReadWrite',
                r'Principal["\']?\s*:\s*["\']?\*["\']?'
            ],
            description="S3 bucket allows public access which may expose sensitive data.",
            recommendation="Configure proper bucket policies and disable public access blocks.",
            fix_example='"AccessControl": "Private",\n"PublicAccessBlockConfiguration": {\n  "BlockPublicAcls": true,\n  "BlockPublicPolicy": true\n}',
            category="Data Protection",
            cwe_id="CWE-200",
            cvss_score=7.5
        ),
        SecurityRule(
            rule_id="CF002",
            title="Open Security Group",
            severity="critical",
            patterns=[
                r'CidrIp["\']?\s*:\s*["\']?0\.0\.0\.0/0["\']?',
                r'IpProtocol["\']?\s*:\s*["\']?-1["\']?'
            ],
            description="Security group allows traffic from any IP address or all protocols.",
            recommendation="Restrict access to specific IP ranges and required protocols only.",
            fix_example='"CidrIp": "10.0.0.0/8",\n"IpProtocol": "tcp",\n"FromPort": 80,\n"ToPort": 80',
            category="Network Security",
            cwe_id="CWE-16",
            cvss_score=9.0
        )
    ]

def get_kubernetes_rules() -> List[SecurityRule]:
    """Get Kubernetes security rules"""
    return [
        SecurityRule(
            rule_id="K8S001",
            title="Container Running as Root",
            severity="high",
            patterns=[
                r'runAsUser\s*:\s*0',
                r'runAsRoot\s*:\s*true',
                r'(?!.*runAsNonRoot\s*:\s*true)'
            ],
            description="Container is configured to run as root user, increasing attack surface.",
            recommendation="Configure containers to run as non-root user with minimal privileges.",
            fix_example='securityContext:\n  runAsUser: 1000\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true',
            category="Container Security",
            cwe_id="CWE-250",
            cvss_score=6.0
        ),
        SecurityRule(
            rule_id="K8S002",
            title="Privileged Container",
            severity="critical",
            patterns=[
                r'privileged\s*:\s*true',
                r'allowPrivilegeEscalation\s*:\s*true'
            ],
            description="Container is running in privileged mode, which grants access to host resources.",
            recommendation="Avoid privileged containers unless absolutely necessary. Use specific capabilities instead.",
            fix_example='securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop:\n    - ALL',
            category="Container Security",
            cwe_id="CWE-250",
            cvss_score=8.5
        ),
        SecurityRule(
            rule_id="K8S003",
            title="Missing Resource Limits",
            severity="medium",
            patterns=[
                r'containers\s*:(?!.*limits\s*:)',
                r'(?!.*resources\s*:.*limits)'
            ],
            description="Container has no resource limits defined, which may lead to resource exhaustion.",
            recommendation="Set appropriate CPU and memory limits to prevent resource starvation.",
            fix_example='resources:\n  limits:\n    cpu: "500m"\n    memory: "512Mi"\n  requests:\n    cpu: "250m"\n    memory: "256Mi"',
            category="Resource Management",
            cwe_id="CWE-400",
            cvss_score=4.0
        )
    ]

def get_all_security_rules() -> Dict[str, List[SecurityRule]]:
    """Get all security rules for different IaC platforms"""
    return {
        "terraform": get_terraform_rules(),
        "cloudformation": get_cloudformation_rules(),
        "kubernetes": get_kubernetes_rules()
    }