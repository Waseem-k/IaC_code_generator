"""
AI-powered code remediation using Google Gemini API
"""
import re
import streamlit as st
from datetime import datetime
from typing import List
from src.models import SecurityVulnerability
from src.config import load_config

def generate_ai_fix(vulnerabilities: List[SecurityVulnerability], 
                   code_content: str, iac_type: str):
    """Generate AI-powered fixes for security vulnerabilities"""
    
    if not vulnerabilities:
        st.info("No vulnerabilities to fix!")
        return
    
    with st.spinner("Sending vulnerabilities to Gemini AI for remediation..."):
        try:
            from google import genai
            from google.genai import types
            
            # Load configuration
            config = load_config()
            gemini_api_key = config.get('gemini_api_key')
            
            if not gemini_api_key:
                st.error("GEMINI_API_KEY not found in configuration. Please check your app_config.properties file.")
                return
            
            # Initialize Gemini client
            client = genai.Client(api_key=gemini_api_key)
            
            # Prepare detailed prompt with vulnerabilities
            vulnerabilities_summary = "\n".join([
                f"- {vuln.severity.upper()}: {vuln.title} (Line {vuln.line_number}): {vuln.description}"
                for vuln in vulnerabilities
            ])
            
            prompt = _create_remediation_prompt(code_content, vulnerabilities_summary, iac_type)
            
            # Generate content using Gemini
            response = client.models.generate_content(
                model="gemini-2.0-flash-exp",
                config=types.GenerateContentConfig(
                    system_instruction=_get_system_instruction(),
                    temperature=0.1,
                    max_output_tokens=4000
                ),
                contents=prompt
            )
            
            if response and response.text:
                _display_ai_response(response.text, iac_type)
            else:
                st.error("No response received from Gemini AI")
                
        except ImportError:
            st.error("Google GenAI package not installed. Run: pip install google-genai")
        except Exception as e:
            st.error(f"Error calling Gemini API: {str(e)}")
            st.info("Make sure your API key is valid and you have sufficient quota.")

def _create_remediation_prompt(code_content: str, vulnerabilities_summary: str, iac_type: str) -> str:
    """Create the remediation prompt for the AI"""
    return f"""You are an expert Infrastructure as Code (IaC) security consultant. 

Given the following {iac_type.title()} configuration with detected security vulnerabilities, provide a completely fixed and secure version of the code that addresses ALL the issues listed below.

ORIGINAL CODE:
```{iac_type}
{code_content}
```

DETECTED VULNERABILITIES:
{vulnerabilities_summary}

Please provide:
1. The complete fixed code with all vulnerabilities remediated
2. A brief summary of the key changes made
3. Explanation of why each change improves security

Ensure the fixed code follows security best practices and maintains functionality while eliminating all identified risks."""

def _get_system_instruction() -> str:
    """Get the system instruction for the AI"""
    return """You are an expert Infrastructure as Code security consultant specializing in Terraform, CloudFormation, and Kubernetes. 

Your role is to:
1. Analyze security vulnerabilities in IaC code
2. Provide secure, production-ready code fixes
3. Follow industry best practices and compliance standards
4. Maintain code functionality while improving security posture
5. Explain security improvements clearly

Always prioritize security while ensuring the code remains functional and maintainable."""

def _display_ai_response(response_text: str, iac_type: str):
    """Display the AI response with proper formatting"""
    st.success("AI-generated security fixes:")

    # Extract code from markdown code blocks
    code_pattern = f'```{iac_type}(.*?)```'
    code_matches = re.findall(code_pattern, response_text, re.DOTALL)
    
    if code_matches:
        st.subheader("Fixed Code:")
        fixed_code = code_matches[0].strip()
        st.code(fixed_code, language=iac_type)
        
        st.download_button(
            "Download Fixed Code",
            fixed_code,
            file_name=f"fixed_{iac_type}_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{iac_type}",
            mime="text/plain"
        )
    
    st.subheader("AI Analysis:")
    st.markdown(response_text)

def generate_security_recommendations(vulnerabilities: List[SecurityVulnerability], iac_type: str) -> str:
    """Generate general security recommendations based on found vulnerabilities"""
    
    if not vulnerabilities:
        return "Your configuration appears secure! Continue following security best practices."
    
    recommendations = []
    categories = set(vuln.category for vuln in vulnerabilities)
    severities = set(vuln.severity for vuln in vulnerabilities)
    
    # General recommendations based on categories
    category_recommendations = {
        "Data Protection": [
            "Implement data encryption at rest and in transit",
            "Use private access controls for sensitive resources",
            "Enable logging and monitoring for data access"
        ],
        "Network Security": [
            "Implement network segmentation and least privilege access",
            "Use security groups and NACLs to restrict traffic",
            "Consider using VPN or private endpoints"
        ],
        "Container Security": [
            "Run containers with non-root users",
            "Implement resource limits and security contexts",
            "Use minimal base images and scan for vulnerabilities"
        ],
        "Access Control": [
            "Follow principle of least privilege",
            "Use role-based access control (RBAC)",
            "Regularly audit and rotate credentials"
        ],
        "Encryption": [
            "Enable encryption for all data stores",
            "Use customer-managed encryption keys when possible",
            "Implement key rotation policies"
        ],
        "Database Security": [
            "Enable database encryption and backup encryption",
            "Use database-specific security features",
            "Implement proper access controls and auditing"
        ]
    }
    
    for category in categories:
        if category in category_recommendations:
            recommendations.extend(category_recommendations[category])
    
    # Severity-based urgency
    if 'critical' in severities:
        urgency_note = "🔴 CRITICAL: Address immediately to prevent potential security breaches."
    elif 'high' in severities:
        urgency_note = "🟠 HIGH PRIORITY: Address within 24-48 hours."
    elif 'medium' in severities:
        urgency_note = "🟡 MEDIUM PRIORITY: Address within 1 week."
    else:
        urgency_note = "🟢 LOW PRIORITY: Address during next maintenance window."
    
    recommendation_text = f"""
## Security Recommendations

{urgency_note}

### Immediate Actions:
"""
    
    for i, rec in enumerate(set(recommendations), 1):
        recommendation_text += f"\n{i}. {rec}"
    
    recommendation_text += f"""

### Platform-Specific Best Practices for {iac_type.title()}:

"""
    
    # Platform-specific recommendations
    platform_recommendations = {
        "terraform": [
            "Use Terraform state encryption and remote state",
            "Implement policy as code with tools like Sentinel or OPA",
            "Use terraform validate and security scanning in CI/CD",
            "Pin provider versions for consistency"
        ],
        "cloudformation": [
            "Use CloudFormation drift detection",
            "Implement stack policies for protection",
            "Use CloudFormation Guard for policy validation",
            "Enable CloudTrail for API logging"
        ],
        "kubernetes": [
            "Implement Pod Security Standards",
            "Use Network Policies for traffic control",
            "Enable RBAC and audit logging",
            "Regularly update cluster and scan images"
        ]
    }
    
    if iac_type in platform_recommendations:
        for i, rec in enumerate(platform_recommendations[iac_type], 1):
            recommendation_text += f"\n{i}. {rec}"
    
    return recommendation_text