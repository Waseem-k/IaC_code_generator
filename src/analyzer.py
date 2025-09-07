"""
Core security analyzer for Infrastructure as Code files
"""
import re
from typing import List
from src.models import SecurityVulnerability
from src.security_rules import get_all_security_rules

class IaCSecurityAnalyzer:
    """Main security analyzer class"""
    
    def __init__(self):
        self.security_rules = get_all_security_rules()
    
    def analyze_code(self, code: str, iac_type: str) -> List[SecurityVulnerability]:
        """Analyze IaC code for security vulnerabilities with improved context awareness"""
        vulnerabilities = []
        rules = self.security_rules.get(iac_type, [])
        
        # Remove comments and normalize whitespace
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
            vulnerabilities.extend(
                self._analyze_rule(rule, clean_code, lines, clean_lines, iac_type)
            )
        
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
    
    def _analyze_rule(self, rule, clean_code: str, lines: List[str], 
                     clean_lines: List[str], iac_type: str) -> List[SecurityVulnerability]:
        """Analyze a specific security rule against the code"""
        vulnerabilities = []
        
        if rule.rule_id == "TF002":  # Special handling for EBS encryption
            vulnerabilities.extend(
                self._check_ebs_encryption(rule, clean_code, lines)
            )
        elif rule.rule_id == "TF003":  # Special handling for security groups
            vulnerabilities.extend(
                self._check_security_groups(rule, clean_code, lines)
            )
        elif rule.rule_id == "TF004":  # Special handling for RDS encryption
            vulnerabilities.extend(
                self._check_rds_encryption(rule, clean_code, lines)
            )
        else:  # Default pattern matching for other rules
            vulnerabilities.extend(
                self._check_default_patterns(rule, lines, clean_lines, iac_type)
            )
        
        return vulnerabilities
    
    def _check_ebs_encryption(self, rule, clean_code: str, lines: List[str]) -> List[SecurityVulnerability]:
        """Check for EBS encryption issues"""
        vulnerabilities = []
        
        # Check for resource blocks that don't have encryption enabled
        ebs_volume_pattern = r'resource\s+["\']aws_ebs_volume["\'][^{]*{([^{}]*(?:{[^{}]*}[^{}]*)*)[^{}]*}'
        ebs_instance_pattern = r'ebs_block_device\s*{([^{}]*(?:{[^{}]*}[^{}]*)*)[^{}]*}'
        
        for match_pattern, resource_type in [(ebs_volume_pattern, "aws_ebs_volume"), 
                                           (ebs_instance_pattern, "ebs_block_device")]:
            matches = re.finditer(match_pattern, clean_code, re.DOTALL | re.IGNORECASE)
            for match in matches:
                block_content = match.group(1)
                if not re.search(r'encrypted\s*=\s*true', block_content, re.IGNORECASE):
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
        
        return vulnerabilities
    
    def _check_security_groups(self, rule, clean_code: str, lines: List[str]) -> List[SecurityVulnerability]:
        """Check for security group issues"""
        vulnerabilities = []
        
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
        
        return vulnerabilities
    
    def _check_rds_encryption(self, rule, clean_code: str, lines: List[str]) -> List[SecurityVulnerability]:
        """Check for RDS encryption issues"""
        vulnerabilities = []
        
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
        
        return vulnerabilities
    
    def _check_default_patterns(self, rule, lines: List[str], clean_lines: List[str], 
                               iac_type: str) -> List[SecurityVulnerability]:
        """Check default pattern matching for rules"""
        vulnerabilities = []
        
        for pattern in rule.patterns:
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
        
        return vulnerabilities