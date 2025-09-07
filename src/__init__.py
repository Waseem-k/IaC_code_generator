"""
IaC Security Policy Generator

A comprehensive security analysis tool for Infrastructure as Code files.
Supports Terraform, CloudFormation, and Kubernetes configurations.
"""

__version__ = "1.0.0"
__author__ = "Waseem Khan"
__email__ = "khan.waseem1703@gmail.com"
__description__ = "Analyze Infrastructure as Code files for security vulnerabilities, and fix with AI assistance."

from src.models import SecurityVulnerability, SecurityRule
from src.analyzer import IaCSecurityAnalyzer
from src.security_rules import get_all_security_rules
from src.visualization import (
    create_severity_chart,
    create_category_chart,
    create_cvss_distribution
)
from src.report_generator import (
    export_report,
    export_csv_report,
    generate_markdown_report
)
from src.ai_remediation import generate_ai_fix
from src.config import load_config

__all__ = [
    'SecurityVulnerability',
    'SecurityRule',
    'IaCSecurityAnalyzer',
    'get_all_security_rules',
    'create_severity_chart',
    'create_category_chart',
    'create_cvss_distribution',
    'export_report',
    'export_csv_report',
    'generate_markdown_report',
    'generate_ai_fix',
    'load_config'
]