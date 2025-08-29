import streamlit as st
import re
import json
import yaml
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import hashlib
import io
import requests
from jproperties import Properties

# Load configuration from properties file
configs = Properties()
with open('app_config.properties', 'rb') as config_file:
    configs.load(config_file)
GEMINI_API_KEY = configs.get("GEMINI_API_KEY").data
# QDRANT_API_KEY = configs.get("QDRANT_API_KEY")
# Configure Streamlit page
st.set_page_config(
    page_title="IaC Security Policy Generator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

@dataclass
class SecurityVulnerability:
    """Data class for security vulnerabilities"""
    title: str
    severity: str
    description: str
    line_number: Optional[int]
    context: Optional[str]
    recommendation: str
    fix_example: Optional[str]
    rule_id: str
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

@dataclass
class SecurityRule:
    """Data class for security rules"""
    rule_id: str
    title: str
    severity: str
    patterns: List[str]
    description: str
    recommendation: str
    fix_example: Optional[str]
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

class IaCSecurityAnalyzer:
    """Main security analyzer class"""
    
    def __init__(self):
        self.security_rules = self._initialize_security_rules()
        
    # def _initialize_security_rules(self) -> Dict[str, List[SecurityRule]]:
    #     """Initialize security rules for different IaC platforms"""
    #     return {
    #         "terraform": [
    #             SecurityRule(
    #                 rule_id="TF001",
    #                 title="Public S3 Bucket",
    #                 severity="high",
    #                 patterns=[
    #                     r'acl\s*=\s*["\']public-read["\']',
    #                     r'acl\s*=\s*["\']public-read-write["\']',
    #                     r'bucket_public_access_block\s*{[^}]*block_public_acls\s*=\s*false',
    #                     r'bucket_public_access_block\s*{[^}]*ignore_public_acls\s*=\s*false'
    #                 ],
    #                 description="S3 bucket is configured with public access, which may expose sensitive data to unauthorized users.",
    #                 recommendation="Use private ACL and configure specific bucket policies. Enable S3 bucket public access block.",
    #                 fix_example='acl = "private"\n\nbucket_public_access_block {\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}',
    #                 category="Data Protection",
    #                 cwe_id="CWE-200",
    #                 cvss_score=7.5
    #             ),
    #             SecurityRule(
    #                 rule_id="TF002",
    #                 title="Unencrypted EBS Volume",
    #                 severity="high",
    #                 patterns=[
    #                     r'resource\s+["\']aws_ebs_volume["\'][^}]*(?!encrypted\s*=\s*true)',
    #                     r'resource\s+["\']aws_instance["\'][^}]*ebs_block_device[^}]*(?!encrypted\s*=\s*true)'
    #                 ],
    #                 description="EBS volumes are not encrypted, potentially exposing sensitive data at rest.",
    #                 recommendation="Enable encryption for all EBS volumes using AWS KMS keys to protect data at rest.",
    #                 fix_example='encrypted = true\nkms_key_id = aws_kms_key.ebs.arn',
    #                 category="Encryption",
    #                 cwe_id="CWE-311",
    #                 cvss_score=6.5
    #             ),
    #             SecurityRule(
    #                 rule_id="TF003",
    #                 title="Open Security Group",
    #                 severity="critical",
    #                 patterns=[
    #                     r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']',
    #                     r'from_port\s*=\s*0[^}]*to_port\s*=\s*65535[^}]*cidr_blocks',
    #                     r'protocol\s*=\s*["\']tcp["\'][^}]*from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']'
    #                 ],
    #                 description="Security group allows unrestricted inbound access from the internet (0.0.0.0/0).",
    #                 recommendation="Restrict inbound rules to specific IP ranges, security groups, or use AWS Systems Manager Session Manager for SSH access.",
    #                 fix_example='cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12"]\n# Or use security group references\nsecurity_groups = [aws_security_group.app.id]',
    #                 category="Network Security",
    #                 cwe_id="CWE-16",
    #                 cvss_score=9.0
    #             ),
    #             SecurityRule(
    #                 rule_id="TF004",
    #                 title="Unencrypted RDS Instance",
    #                 severity="high",
    #                 patterns=[
    #                     r'resource\s+["\']aws_db_instance["\'][^}]*(?!storage_encrypted\s*=\s*true)'
    #                 ],
    #                 description="RDS database instance is not encrypted, potentially exposing sensitive data.",
    #                 recommendation="Enable encryption for RDS instances and consider encryption in transit.",
    #                 fix_example='storage_encrypted = true\nkms_key_id = aws_kms_key.rds.arn',
    #                 category="Database Security",
    #                 cwe_id="CWE-311",
    #                 cvss_score=7.0
    #             ),
    #             SecurityRule(
    #                 rule_id="TF005",
    #                 title="IAM Policy with Wildcard Actions",
    #                 severity="medium",
    #                 patterns=[
    #                     r'["\']Action["\']\s*[:=]\s*["\'][*]["\']',
    #                     r'["\']Resource["\']\s*[:=]\s*["\'][*]["\']'
    #                 ],
    #                 description="IAM policy uses wildcard (*) for actions or resources, potentially granting excessive permissions.",
    #                 recommendation="Follow the principle of least privilege by specifying exact actions and resources.",
    #                 fix_example='"Action": ["s3:GetObject", "s3:PutObject"],\n"Resource": ["arn:aws:s3:::my-bucket/*"]',
    #                 category="Access Control",
    #                 cwe_id="CWE-269",
    #                 cvss_score=5.5
    #             )
    #         ],
    #         "cloudformation": [
    #             SecurityRule(
    #                 rule_id="CF001",
    #                 title="Public S3 Bucket Access",
    #                 severity="high",
    #                 patterns=[
    #                     r'AccessControl["\']?\s*:\s*["\']?PublicRead',
    #                     r'AccessControl["\']?\s*:\s*["\']?PublicReadWrite',
    #                     r'Principal["\']?\s*:\s*["\']?\*["\']?'
    #                 ],
    #                 description="S3 bucket allows public access which may expose sensitive data.",
    #                 recommendation="Configure proper bucket policies and disable public access blocks.",
    #                 fix_example='"AccessControl": "Private",\n"PublicAccessBlockConfiguration": {\n  "BlockPublicAcls": true,\n  "BlockPublicPolicy": true\n}',
    #                 category="Data Protection",
    #                 cwe_id="CWE-200",
    #                 cvss_score=7.5
    #             ),
    #             SecurityRule(
    #                 rule_id="CF002",
    #                 title="Open Security Group",
    #                 severity="critical",
    #                 patterns=[
    #                     r'CidrIp["\']?\s*:\s*["\']?0\.0\.0\.0/0["\']?',
    #                     r'IpProtocol["\']?\s*:\s*["\']?-1["\']?'
    #                 ],
    #                 description="Security group allows traffic from any IP address or all protocols.",
    #                 recommendation="Restrict access to specific IP ranges and required protocols only.",
    #                 fix_example='"CidrIp": "10.0.0.0/8",\n"IpProtocol": "tcp",\n"FromPort": 80,\n"ToPort": 80',
    #                 category="Network Security",
    #                 cwe_id="CWE-16",
    #                 cvss_score=9.0
    #             )
    #         ],
    #         "kubernetes": [
    #             SecurityRule(
    #                 rule_id="K8S001",
    #                 title="Container Running as Root",
    #                 severity="high",
    #                 patterns=[
    #                     r'runAsUser\s*:\s*0',
    #                     r'runAsRoot\s*:\s*true',
    #                     r'(?!.*runAsNonRoot\s*:\s*true)'
    #                 ],
    #                 description="Container is configured to run as root user, increasing attack surface.",
    #                 recommendation="Configure containers to run as non-root user with minimal privileges.",
    #                 fix_example='securityContext:\n  runAsUser: 1000\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true',
    #                 category="Container Security",
    #                 cwe_id="CWE-250",
    #                 cvss_score=6.0
    #             ),
    #             SecurityRule(
    #                 rule_id="K8S002",
    #                 title="Privileged Container",
    #                 severity="critical",
    #                 patterns=[
    #                     r'privileged\s*:\s*true',
    #                     r'allowPrivilegeEscalation\s*:\s*true'
    #                 ],
    #                 description="Container is running in privileged mode, which grants access to host resources.",
    #                 recommendation="Avoid privileged containers unless absolutely necessary. Use specific capabilities instead.",
    #                 fix_example='securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop:\n    - ALL',
    #                 category="Container Security",
    #                 cwe_id="CWE-250",
    #                 cvss_score=8.5
    #             ),
    #             SecurityRule(
    #                 rule_id="K8S003",
    #                 title="Missing Resource Limits",
    #                 severity="medium",
    #                 patterns=[
    #                     r'containers\s*:(?!.*limits\s*:)',
    #                     r'(?!.*resources\s*:.*limits)'
    #                 ],
    #                 description="Container has no resource limits defined, which may lead to resource exhaustion.",
    #                 recommendation="Set appropriate CPU and memory limits to prevent resource starvation.",
    #                 fix_example='resources:\n  limits:\n    cpu: "500m"\n    memory: "512Mi"\n  requests:\n    cpu: "250m"\n    memory: "256Mi"',
    #                 category="Resource Management",
    #                 cwe_id="CWE-400",
    #                 cvss_score=4.0
    #             )
    #         ]
    #     }

    def _initialize_security_rules(self) -> Dict[str, List[SecurityRule]]:
        """Initialize security rules for different IaC platforms"""
        return {
            "terraform": [
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
            ],
            "cloudformation": [
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
            ],
            "kubernetes": [
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
        }

    def analyze_code(self, code: str, iac_type: str) -> List[SecurityVulnerability]:
        """Analyze IaC code for security vulnerabilities with improved context awareness"""
        vulnerabilities = []
        rules = self.security_rules.get(iac_type, [])
        
        # Remove comments and normalize whitespace for better analysis
        lines = code.split('\n')
        clean_lines = []
        for line in lines:
            # Remove inline comments but preserve the line structure
            if '#' in line:
                line_without_comment = line.split('#')[0].rstrip()
            else:
                line_without_comment = line
            clean_lines.append(line_without_comment)
        
        # Join lines to analyze blocks properly
        clean_code = '\n'.join(clean_lines)
        
        for rule in rules:
            for pattern in rule.patterns:
                if rule.rule_id == "TF002":  # Special handling for EBS encryption
                    # Check for resource blocks that don't have encryption enabled
                    ebs_volume_pattern = r'resource\s+["\']aws_ebs_volume["\'][^{]*{([^{}]*(?:{[^{}]*}[^{}]*)*)[^{}]*}'
                    ebs_instance_pattern = r'ebs_block_device\s*{([^{}]*(?:{[^{}]*}[^{}]*)*)[^{}]*}'
                    
                    for match_pattern, resource_type in [(ebs_volume_pattern, "aws_ebs_volume"), (ebs_instance_pattern, "ebs_block_device")]:
                        matches = re.finditer(match_pattern, clean_code, re.DOTALL | re.IGNORECASE)
                        for match in matches:
                            block_content = match.group(1)
                            if not re.search(r'encrypted\s*=\s*true', block_content, re.IGNORECASE):
                                # Find the line number
                                line_start = clean_code[:match.start()].count('\n') + 1
                                context_line = lines[line_start - 1] if line_start <= len(lines) else ""
                                
                                vulnerability = SecurityVulnerability(
                                    title=rule.title,
                                    severity=rule.severity,
                                    description=rule.description,
                                    line_number=line_start,
                                    context=context_line.strip(),
                                    recommendation=rule.recommendation,
                                    fix_example=rule.fix_example,
                                    rule_id=rule.rule_id,
                                    category=rule.category,
                                    cwe_id=rule.cwe_id,
                                    cvss_score=rule.cvss_score
                                )
                                vulnerabilities.append(vulnerability)
                
                elif rule.rule_id == "TF003":  # Special handling for security groups
                    # Only flag ingress rules with 0.0.0.0/0
                    ingress_pattern = r'ingress\s*{([^{}]*(?:{[^{}]*}[^{}]*)*)[^{}]*}'
                    matches = re.finditer(ingress_pattern, clean_code, re.DOTALL | re.IGNORECASE)
                    for match in matches:
                        ingress_block = match.group(1)
                        if re.search(r'cidr_blocks\s*=\s*\[[^]]*["\']0\.0\.0\.0/0["\']', ingress_block, re.IGNORECASE):
                            line_start = clean_code[:match.start()].count('\n') + 1
                            context_line = lines[line_start - 1] if line_start <= len(lines) else ""
                            
                            vulnerability = SecurityVulnerability(
                                title=rule.title,
                                severity=rule.severity,
                                description=rule.description,
                                line_number=line_start,
                                context=context_line.strip(),
                                recommendation=rule.recommendation,
                                fix_example=rule.fix_example,
                                rule_id=rule.rule_id,
                                category=rule.category,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score
                            )
                            vulnerabilities.append(vulnerability)
                
                elif rule.rule_id == "TF004":  # Special handling for RDS encryption
                    rds_pattern = r'resource\s+["\']aws_db_instance["\'][^{]*{([^{}]*(?:{[^{}]*}[^{}]*)*)[^{}]*}'
                    matches = re.finditer(rds_pattern, clean_code, re.DOTALL | re.IGNORECASE)
                    for match in matches:
                        rds_block = match.group(1)
                        if not re.search(r'storage_encrypted\s*=\s*true', rds_block, re.IGNORECASE):
                            line_start = clean_code[:match.start()].count('\n') + 1
                            context_line = lines[line_start - 1] if line_start <= len(lines) else ""
                            
                            vulnerability = SecurityVulnerability(
                                title=rule.title,
                                severity=rule.severity,
                                description=rule.description,
                                line_number=line_start,
                                context=context_line.strip(),
                                recommendation=rule.recommendation,
                                fix_example=rule.fix_example,
                                rule_id=rule.rule_id,
                                category=rule.category,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score
                            )
                            vulnerabilities.append(vulnerability)
                
                else:  # Default pattern matching for other rules
                    for line_num, line in enumerate(lines, 1):
                        clean_line = clean_lines[line_num - 1]
                        if clean_line.strip() and re.search(pattern, clean_line, re.IGNORECASE):
                            vulnerability = SecurityVulnerability(
                                title=rule.title,
                                severity=rule.severity,
                                description=rule.description,
                                line_number=line_num,
                                context=line.strip(),
                                recommendation=rule.recommendation,
                                fix_example=rule.fix_example,
                                rule_id=rule.rule_id,
                                category=rule.category,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score
                            )
                            vulnerabilities.append(vulnerability)
        
        # Remove duplicates based on rule_id and line_number
        seen = set()
        unique_vulnerabilities = []
        for vuln in vulnerabilities:
            key = (vuln.rule_id, vuln.line_number)
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        # Sort by severity and CVSS score
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        unique_vulnerabilities.sort(
            key=lambda x: (severity_order.get(x.severity, 0), x.cvss_score or 0), 
            reverse=True
        )
        
        return unique_vulnerabilities   
    # def analyze_code(self, code: str, iac_type: str) -> List[SecurityVulnerability]:
    #     """Analyze IaC code for security vulnerabilities"""
    #     vulnerabilities = []
    #     rules = self.security_rules.get(iac_type, [])
        
    #     lines = code.split('\n')
        
    #     for rule in rules:
    #         for pattern in rule.patterns:
    #             for line_num, line in enumerate(lines, 1):
    #                 if re.search(pattern, line, re.IGNORECASE):
    #                     vulnerability = SecurityVulnerability(
    #                         title=rule.title,
    #                         severity=rule.severity,
    #                         description=rule.description,
    #                         line_number=line_num,
    #                         context=line.strip(),
    #                         recommendation=rule.recommendation,
    #                         fix_example=rule.fix_example,
    #                         rule_id=rule.rule_id,
    #                         category=rule.category,
    #                         cwe_id=rule.cwe_id,
    #                         cvss_score=rule.cvss_score
    #                     )
    #                     vulnerabilities.append(vulnerability)
        
    #     # Sort by severity and CVSS score
    #     severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    #     vulnerabilities.sort(
    #         key=lambda x: (severity_order.get(x.severity, 0), x.cvss_score or 0), 
    #         reverse=True
    #     )
        
    #     return vulnerabilities

def create_severity_chart(vulnerabilities: List[SecurityVulnerability]):
    """Create severity distribution chart"""
    severity_counts = {}
    for vuln in vulnerabilities:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
    
    colors = {
        'critical': '#e74c3c',
        'high': '#e67e22',
        'medium': '#f39c12',
        'low': '#f1c40f'
    }
    
    fig = px.pie(
        values=list(severity_counts.values()),
        names=list(severity_counts.keys()),
        title="Security Issues by Severity",
        color=list(severity_counts.keys()),
        color_discrete_map=colors
    )
    
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(showlegend=True, height=400)
    
    return fig

def create_category_chart(vulnerabilities: List[SecurityVulnerability]):
    """Create category distribution chart"""
    category_counts = {}
    for vuln in vulnerabilities:
        category_counts[vuln.category] = category_counts.get(vuln.category, 0) + 1
    
    fig = px.bar(
        x=list(category_counts.keys()),
        y=list(category_counts.values()),
        title="Security Issues by Category",
        color=list(category_counts.values()),
        color_continuous_scale="Reds"
    )
    
    fig.update_layout(
        xaxis_title="Security Categories",
        yaxis_title="Number of Issues",
        showlegend=False,
        height=400
    )
    
    return fig

def create_cvss_distribution(vulnerabilities: List[SecurityVulnerability]):
    """Create CVSS score distribution"""
    cvss_scores = [vuln.cvss_score for vuln in vulnerabilities if vuln.cvss_score]
    
    if not cvss_scores:
        return None
    
    fig = px.histogram(
        x=cvss_scores,
        nbins=10,
        title="CVSS Score Distribution",
        color_discrete_sequence=['#3498db']
    )
    
    fig.update_layout(
        xaxis_title="CVSS Score",
        yaxis_title="Number of Vulnerabilities",
        height=400
    )
    
    return fig

def export_report(vulnerabilities: List[SecurityVulnerability], iac_type: str) -> str:
    """Export vulnerabilities to JSON report"""
    report = {
        "scan_timestamp": datetime.now().isoformat(),
        "iac_type": iac_type,
        "total_vulnerabilities": len(vulnerabilities),
        "severity_summary": {},
        "vulnerabilities": []
    }
    
    # Calculate severity summary
    for vuln in vulnerabilities:
        report["severity_summary"][vuln.severity] = report["severity_summary"].get(vuln.severity, 0) + 1
    
    # Add vulnerabilities
    for vuln in vulnerabilities:
        report["vulnerabilities"].append(asdict(vuln))
    
    return json.dumps(report, indent=2)

def main():
    """Main Streamlit application"""
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .vulnerability-card {
        border-left: 5px solid;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 5px;
        background-color: #f8f9fa;
    }
    .critical { border-left-color: #e74c3c; }
    .high { border-left-color: #e67e22; }
    .medium { border-left-color: #f39c12; }
    .low { border-left-color: #f1c40f; }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ IaC Security Policy Generator</h1>
        <p>Analyze Infrastructure as Code files for security vulnerabilities and compliance issues</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize analyzer
    analyzer = IaCSecurityAnalyzer()
    
    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        iac_type = st.selectbox(
            "Select IaC Platform",
            ["terraform", "cloudformation", "kubernetes"],
            format_func=lambda x: x.title()
        )
        
        st.subheader("📁 Input Options")
        input_method = st.radio(
            "Choose input method:",
            ["Upload File", "Paste Code"]
        )
        
        # Analysis settings
        st.subheader("🔍 Analysis Settings")
        show_low_severity = st.checkbox("Include Low Severity Issues", value=True)
        show_line_numbers = st.checkbox("Show Line Numbers", value=True)
        enable_advanced_rules = st.checkbox("Enable Advanced Rules", value=False)
    
    # Main content area
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📝 Input Code")
        
        code_content = ""
        
        if input_method == "Upload File":
            uploaded_file = st.file_uploader(
                "Choose your IaC file",
                type=['tf', 'json', 'yaml', 'yml'],
                help="Upload Terraform (.tf), CloudFormation (.json/.yaml), or Kubernetes (.yaml/.yml) files"
            )
            
            if uploaded_file:
                try:
                    code_content = uploaded_file.read().decode('utf-8')
                    st.success(f"✅ File uploaded: {uploaded_file.name}")
                    
                    # Auto-detect IaC type based on file extension or content
                    file_extension = uploaded_file.name.split('.')[-1].lower()
                    if file_extension == 'tf':
                        iac_type = 'terraform'
                    elif 'AWSTemplateFormatVersion' in code_content or 'Resources:' in code_content:
                        iac_type = 'cloudformation'
                    elif 'apiVersion' in code_content or 'kind:' in code_content:
                        iac_type = 'kubernetes'
                        
                except Exception as e:
                    st.error(f"❌ Error reading file: {str(e)}")
        else:
            code_content = st.text_area(
                "Paste your IaC code here:",
                height=300,
                placeholder=f"Paste your {iac_type.title()} configuration here..."
            )
        
        # Display code preview
        if code_content:
            with st.expander("📖 Code Preview"):
                st.code(code_content, language=iac_type)
    
    with col2:
        st.subheader("🔍 Analysis Results")
        
        if code_content and st.button("🚀 Analyze Security", type="primary"):
            with st.spinner("Analyzing code for security vulnerabilities..."):
                vulnerabilities = analyzer.analyze_code(code_content, iac_type)
                
                # Filter vulnerabilities based on settings
                if not show_low_severity:
                    vulnerabilities = [v for v in vulnerabilities if v.severity != 'low']
                
                # Store results in session state
                st.session_state.vulnerabilities = vulnerabilities
                st.session_state.iac_type = iac_type
                st.session_state.code_content = code_content
        
        # Display results if available
        if hasattr(st.session_state, 'vulnerabilities'):
            vulnerabilities = st.session_state.vulnerabilities
            
            if vulnerabilities:
                # Summary metrics
                st.subheader("📊 Summary")
                
                col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)
                
                severity_counts = {}
                for vuln in vulnerabilities:
                    severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
                
                with col_metric1:
                    st.metric(
                        "Critical",
                        severity_counts.get('critical', 0),
                        delta=None,
                        delta_color="inverse"
                    )
                
                with col_metric2:
                    st.metric(
                        "High",
                        severity_counts.get('high', 0),
                        delta=None,
                        delta_color="inverse"
                    )
                
                with col_metric3:
                    st.metric(
                        "Medium",
                        severity_counts.get('medium', 0),
                        delta=None,
                        delta_color="inverse"
                    )
                
                with col_metric4:
                    st.metric(
                        "Low",
                        severity_counts.get('low', 0),
                        delta=None,
                        delta_color="inverse"
                    )
                
                # Detailed vulnerabilities
                st.subheader("🚨 Detailed Findings")
                
                for i, vuln in enumerate(vulnerabilities):
                    with st.expander(f"{vuln.severity.upper()}: {vuln.title} ({vuln.rule_id})"):
                        
                        col_info, col_details = st.columns([2, 1])
                        
                        with col_info:
                            st.write("**Description:**")
                            st.write(vuln.description)
                            
                            if show_line_numbers and vuln.line_number:
                                st.write(f"**Line:** {vuln.line_number}")
                            
                            if vuln.context:
                                st.write("**Code Context:**")
                                st.code(vuln.context, language=iac_type)
                            
                            st.write("**Recommendation:**")
                            st.write(vuln.recommendation)
                            
                            if vuln.fix_example:
                                st.write("**Fix Example:**")
                                st.code(vuln.fix_example, language=iac_type)
                        
                        with col_details:
                            st.write("**Details:**")
                            st.write(f"**Category:** {vuln.category}")
                            if vuln.cwe_id:
                                st.write(f"**CWE ID:** {vuln.cwe_id}")
                            if vuln.cvss_score:
                                st.write(f"**CVSS Score:** {vuln.cvss_score}")
            else:
                st.success("🎉 No security issues found! Your configuration looks secure.")
    
    # Additional analytics section
    if hasattr(st.session_state, 'vulnerabilities') and st.session_state.vulnerabilities:
        st.markdown("---")
        st.subheader("📈 Security Analytics")
        
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            severity_chart = create_severity_chart(st.session_state.vulnerabilities)
            st.plotly_chart(severity_chart, use_container_width=True)
        
        with col_chart2:
            category_chart = create_category_chart(st.session_state.vulnerabilities)
            st.plotly_chart(category_chart, use_container_width=True)
        
        # CVSS distribution
        cvss_chart = create_cvss_distribution(st.session_state.vulnerabilities)
        if cvss_chart:
            st.plotly_chart(cvss_chart, use_container_width=True)
        
        # Export functionality
        st.markdown("---")
        st.subheader("📤 Export Results")
        
        col_export1, col_export2, col_export3 = st.columns(3)
        
        with col_export1:
            if st.button("📄 Export JSON Report"):
                report = export_report(
                    st.session_state.vulnerabilities, 
                    st.session_state.iac_type
                )
                st.download_button(
                    "⬇️ Download JSON Report",
                    report,
                    file_name=f"iac_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col_export2:
            if st.button("📊 Export CSV"):
                df = pd.DataFrame([asdict(v) for v in st.session_state.vulnerabilities])
                csv = df.to_csv(index=False)
                st.download_button(
                    "⬇️ Download CSV",
                    csv,
                    file_name=f"iac_vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col_export3:
            if st.button("📋 Generate Summary"):
                total_vulns = len(st.session_state.vulnerabilities)
                severity_summary = {}
                for vuln in st.session_state.vulnerabilities:
                    severity_summary[vuln.severity] = severity_summary.get(vuln.severity, 0) + 1
                
                summary = f"""
# IaC Security Analysis Summary

**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**IaC Platform:** {st.session_state.iac_type.title()}
**Total Issues Found:** {total_vulns}

## Severity Breakdown:
"""
                for severity, count in severity_summary.items():
                    summary += f"- **{severity.title()}:** {count}\n"
                
                st.markdown(summary)

                # --- Add Fix with AI Button ---
        st.markdown("---")
        st.subheader("🛠️ AI Remediation")

        if st.button("🤖 Fix with AI"):
            with st.spinner("Sending vulnerabilities to Gemini AI for remediation..."):
                        try:
                            from google import genai
                            from google.genai import types
                            
                            # Initialize Gemini client
                            client = genai.Client(api_key=GEMINI_API_KEY)
                            
                            # Prepare detailed prompt with vulnerabilities
                            vulnerabilities_summary = "\n".join([
                                f"- {vuln.severity.upper()}: {vuln.title} (Line {vuln.line_number}): {vuln.description}"
                                for vuln in st.session_state.vulnerabilities
                            ])
                            
                            prompt = f"""You are an expert Infrastructure as Code (IaC) security consultant. 

Given the following {st.session_state.iac_type.title()} configuration with detected security vulnerabilities, provide a completely fixed and secure version of the code that addresses ALL the issues listed below.

ORIGINAL CODE:
```{st.session_state.iac_type}
{st.session_state.code_content}
```

DETECTED VULNERABILITIES:
{vulnerabilities_summary}

Please provide:
1. The complete fixed code with all vulnerabilities remediated
2. A brief summary of the key changes made

Ensure the fixed code follows security best practices and maintains functionality while eliminating all identified risks."""

                            # Generate content using Gemini
                            response = client.models.generate_content(
                                model="gemini-2.0-flash-exp",
                                config=types.GenerateContentConfig(
                                    system_instruction="You are an expert Infrastructure as Code security consultant specializing in Terraform, CloudFormation, and Kubernetes. Provide secure, production-ready code fixes that follow industry best practices.",
                                    temperature=0.1,
                                    max_output_tokens=4000
                                ),
                                contents=prompt
                            )
                            
                            if response and response.text:
                                st.success("✅ AI-generated security fixes:")
                                
                                # Extract code blocks if present
                                fixed_content = response.text
                                
                                # Try to extract code from markdown code blocks
                                code_pattern = f'```{st.session_state.iac_type}(.*?)```'
                                code_matches = re.findall(code_pattern, fixed_content, re.DOTALL)
                                
                                if code_matches:
                                    st.subheader("🔧 Fixed Code:")
                                    st.code(code_matches[0].strip(), language=st.session_state.iac_type)
                                    
                                    # Offer download of fixed code
                                    st.download_button(
                                        "⬇️ Download Fixed Code",
                                        code_matches[0].strip(),
                                        file_name=f"fixed_{st.session_state.iac_type}_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{st.session_state.iac_type}",
                                        mime="text/plain"
                                    )
                                
                                st.subheader("📝 AI Analysis:")
                                st.markdown(fixed_content)
                                
                            else:
                                st.error("❌ No response received from Gemini AI")
                                
                        except ImportError:
                            st.error("❌ Google GenAI package not installed. Run: pip install google-genai")
                        except Exception as e:
                            st.error(f"❌ Error calling Gemini API: {str(e)}")
                            st.info("💡 Make sure your API key is valid and you have sufficient quota.")
if __name__ == "__main__":
    main()