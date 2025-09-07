"""
Report generation functionality for security analysis results
"""
import json
import csv
import io
from datetime import datetime
from dataclasses import asdict
from typing import List, Optional
from src.models import SecurityVulnerability

def export_report(vulnerabilities: List[SecurityVulnerability], iac_type: str) -> str:
    """Export vulnerabilities to JSON report"""
    report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "iac_type": iac_type,
            "total_vulnerabilities": len(vulnerabilities),
            "tool_version": "1.0.0",
            "scan_id": f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        },
        "severity_summary": _calculate_severity_summary(vulnerabilities),
        "category_summary": _calculate_category_summary(vulnerabilities),
        "vulnerabilities": [asdict(vuln) for vuln in vulnerabilities]
    }
    
    return json.dumps(report, indent=2)

def export_csv_report(vulnerabilities: List[SecurityVulnerability]) -> str:
    """Export vulnerabilities to CSV format"""
    output = io.StringIO()
    
    if not vulnerabilities:
        return "No vulnerabilities found"
    
    fieldnames = [
        'rule_id', 'title', 'severity', 'category', 'description',
        'line_number', 'context', 'recommendation', 'fix_example',
        'cwe_id', 'cvss_score'
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for vuln in vulnerabilities:
        writer.writerow(asdict(vuln))
    
    return output.getvalue()

def generate_markdown_report(vulnerabilities: List[SecurityVulnerability], 
                           iac_type: str, code_content: Optional[str] = None) -> str:
    """Generate a comprehensive markdown report"""
    report = []
    
    # Header
    report.append("# IaC Security Analysis Report")
    report.append("")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Platform:** {iac_type.title()}")
    report.append(f"**Total Issues:** {len(vulnerabilities)}")
    report.append("")
    
    # Executive Summary
    report.append("## Executive Summary")
    report.append("")
    
    if vulnerabilities:
        severity_summary = _calculate_severity_summary(vulnerabilities)
        report.append("This security analysis identified the following issues:")
        report.append("")
        
        for severity, count in severity_summary.items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
            report.append(f"- {emoji} **{severity.title()}:** {count} issue(s)")
        
        report.append("")
        report.append("**Immediate action is recommended** for critical and high severity issues.")
    else:
        report.append("✅ **No security issues found.** The configuration appears to follow security best practices.")
    
    report.append("")
    
    # Detailed Findings
    if vulnerabilities:
        report.append("## Detailed Findings")
        report.append("")
        
        # Group by severity
        by_severity = {}
        for vuln in vulnerabilities:
            if vuln.severity not in by_severity:
                by_severity[vuln.severity] = []
            by_severity[vuln.severity].append(vuln)
        
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            if severity in by_severity:
                report.append(f"### {severity.title()} Severity Issues")
                report.append("")
                
                for i, vuln in enumerate(by_severity[severity], 1):
                    report.append(f"#### {i}. {vuln.title} ({vuln.rule_id})")
                    report.append("")
                    report.append(f"**Description:** {vuln.description}")
                    report.append("")
                    
                    if vuln.line_number:
                        report.append(f"**Location:** Line {vuln.line_number}")
                        report.append("")
                    
                    if vuln.context:
                        report.append("**Code Context:**")
                        report.append(f"```{iac_type}")
                        report.append(vuln.context)
                        report.append("```")
                        report.append("")
                    
                    report.append(f"**Recommendation:** {vuln.recommendation}")
                    report.append("")
                    
                    if vuln.fix_example:
                        report.append("**Fix Example:**")
                        report.append(f"```{iac_type}")
                        report.append(vuln.fix_example)
                        report.append("```")
                        report.append("")
                    
                    # Additional metadata
                    metadata = []
                    if vuln.cwe_id:
                        metadata.append(f"CWE: {vuln.cwe_id}")
                    if vuln.cvss_score:
                        metadata.append(f"CVSS Score: {vuln.cvss_score}")
                    if vuln.category:
                        metadata.append(f"Category: {vuln.category}")
                    
                    if metadata:
                        report.append(f"**Additional Info:** {' | '.join(metadata)}")
                        report.append("")
                    
                    report.append("---")
                    report.append("")
    
    # Recommendations
    report.append("## Recommendations")
    report.append("")
    
    if vulnerabilities:
        # Priority recommendations based on severity
        critical_count = len([v for v in vulnerabilities if v.severity == 'critical'])
        high_count = len([v for v in vulnerabilities if v.severity == 'high'])
        
        if critical_count > 0:
            report.append(f"1. **Immediate Action Required:** Address all {critical_count} critical severity issues immediately.")
        if high_count > 0:
            report.append(f"2. **High Priority:** Resolve {high_count} high severity issues within 24-48 hours.")
        
        report.append("3. **Security Review:** Implement regular security scanning in your CI/CD pipeline.")
        report.append("4. **Code Review:** Establish security-focused code review processes.")
        report.append("5. **Training:** Ensure team members are trained on secure IaC practices.")
    else:
        report.append("1. **Maintain Standards:** Continue following current security practices.")
        report.append("2. **Regular Scanning:** Implement automated security scanning in CI/CD.")
        report.append("3. **Stay Updated:** Keep security rules and policies updated.")
    
    report.append("")
    
    # Footer
    report.append("---")
    report.append("*Report generated by IaC Security Policy Generator*")
    
    return "\n".join(report)

def _calculate_severity_summary(vulnerabilities: List[SecurityVulnerability]) -> dict:
    """Calculate severity summary"""
    summary = {}
    for vuln in vulnerabilities:
        summary[vuln.severity] = summary.get(vuln.severity, 0) + 1
    return summary

def _calculate_category_summary(vulnerabilities: List[SecurityVulnerability]) -> dict:
    """Calculate category summary"""
    summary = {}
    for vuln in vulnerabilities:
        summary[vuln.category] = summary.get(vuln.category, 0) + 1
    return summary

def generate_remediation_checklist(vulnerabilities: List[SecurityVulnerability]) -> str:
    """Generate a remediation checklist"""
    if not vulnerabilities:
        return "✅ No issues found - configuration is secure!"
    
    checklist = ["# Security Remediation Checklist", ""]
    
    # Group by severity for prioritization
    by_severity = {}
    for vuln in vulnerabilities:
        if vuln.severity not in by_severity:
            by_severity[vuln.severity] = []
        by_severity[vuln.severity].append(vuln)
    
    severity_order = ['critical', 'high', 'medium', 'low']
    priority_map = {
        'critical': '🔴 URGENT',
        'high': '🟠 HIGH',
        'medium': '🟡 MEDIUM',
        'low': '🟢 LOW'
    }
    
    for severity in severity_order:
        if severity in by_severity:
            checklist.append(f"## {priority_map[severity]} Priority")
            checklist.append("")
            
            for vuln in by_severity[severity]:
                line_info = f" (Line {vuln.line_number})" if vuln.line_number else ""
                checklist.append(f"- [ ] **{vuln.title}**{line_info}")
                checklist.append(f"  - Rule: {vuln.rule_id}")
                checklist.append(f"  - Fix: {vuln.recommendation}")
                checklist.append("")
    
    return "\n".join(checklist)