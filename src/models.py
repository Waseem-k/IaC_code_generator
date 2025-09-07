"""
Data models for IaC Security Policy Generator
"""
from dataclasses import dataclass
from typing import List, Optional

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