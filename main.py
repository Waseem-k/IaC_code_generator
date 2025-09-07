import streamlit as st
from datetime import datetime
import pandas as pd

from src.analyzer import IaCSecurityAnalyzer
from src.visualization import (
    create_severity_chart, 
    create_category_chart, 
    create_cvss_distribution
)
from src.report_generator import export_report
from src.ai_remediation import generate_ai_fix
from src.config import load_config

def init_page_config():
    """Initialize Streamlit page configuration"""
    st.set_page_config(
        page_title="IaC Security Policy Generator",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

def load_custom_css():
    """Load custom CSS styling"""
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

def render_header():
    """Render application header"""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ IaC Security Policy Generator</h1>
        <p>Analyze Infrastructure as Code files for security vulnerabilities and compliance issues</p>
    </div>
    """, unsafe_allow_html=True)

def render_sidebar():
    """Render sidebar configuration"""
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
        
        st.subheader("🔍 Analysis Settings")
        show_low_severity = st.checkbox("Include Low Severity Issues", value=True)
        show_line_numbers = st.checkbox("Show Line Numbers", value=True)
        enable_advanced_rules = st.checkbox("Enable Advanced Rules", value=False)
        
        return {
            'iac_type': iac_type,
            'input_method': input_method,
            'show_low_severity': show_low_severity,
            'show_line_numbers': show_line_numbers,
            'enable_advanced_rules': enable_advanced_rules
        }

def handle_file_input(input_method, iac_type):
    """Handle file input and code pasting"""
    code_content = ""
    detected_type = iac_type
    
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
                
                # Auto-detect IaC type
                file_extension = uploaded_file.name.split('.')[-1].lower()
                if file_extension == 'tf':
                    detected_type = 'terraform'
                elif 'AWSTemplateFormatVersion' in code_content or 'Resources:' in code_content:
                    detected_type = 'cloudformation'
                elif 'apiVersion' in code_content or 'kind:' in code_content:
                    detected_type = 'kubernetes'
                        
            except Exception as e:
                st.error(f"❌ Error reading file: {str(e)}")
    else:
        code_content = st.text_area(
            "Paste your IaC code here:",
            height=300,
            placeholder=f"Paste your {iac_type.title()} configuration here..."
        )
    
    return code_content, detected_type

def render_summary_metrics(vulnerabilities):
    """Render summary metrics"""
    st.subheader("📊 Summary")
    
    col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)
    
    severity_counts = {}
    for vuln in vulnerabilities:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
    
    with col_metric1:
        st.metric("Critical", severity_counts.get('critical', 0), delta=None, delta_color="inverse")
    with col_metric2:
        st.metric("High", severity_counts.get('high', 0), delta=None, delta_color="inverse")
    with col_metric3:
        st.metric("Medium", severity_counts.get('medium', 0), delta=None, delta_color="inverse")
    with col_metric4:
        st.metric("Low", severity_counts.get('low', 0), delta=None, delta_color="inverse")

def render_vulnerability_details(vulnerabilities, settings):
    """Render detailed vulnerability findings"""
    st.subheader("🚨 Detailed Findings")
    
    for vuln in vulnerabilities:
        with st.expander(f"{vuln.severity.upper()}: {vuln.title} ({vuln.rule_id})"):
            col_info, col_details = st.columns([2, 1])
            
            with col_info:
                st.write("**Description:**")
                st.write(vuln.description)
                
                if settings['show_line_numbers'] and vuln.line_number:
                    st.write(f"**Line:** {vuln.line_number}")
                
                if vuln.context:
                    st.write("**Code Context:**")
                    st.code(vuln.context, language=st.session_state.iac_type)
                
                st.write("**Recommendation:**")
                st.write(vuln.recommendation)
                
                if vuln.fix_example:
                    st.write("**Fix Example:**")
                    st.code(vuln.fix_example, language=st.session_state.iac_type)
            
            with col_details:
                st.write("**Details:**")
                st.write(f"**Category:** {vuln.category}")
                if vuln.cwe_id:
                    st.write(f"**CWE ID:** {vuln.cwe_id}")
                if vuln.cvss_score:
                    st.write(f"**CVSS Score:** {vuln.cvss_score}")

def render_analytics_section(vulnerabilities):
    """Render security analytics charts"""
    st.markdown("---")
    st.subheader("📈 Security Analytics")
    
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        severity_chart = create_severity_chart(vulnerabilities)
        st.plotly_chart(severity_chart, use_container_width=True)
    
    with col_chart2:
        category_chart = create_category_chart(vulnerabilities)
        st.plotly_chart(category_chart, use_container_width=True)
    
    cvss_chart = create_cvss_distribution(vulnerabilities)
    if cvss_chart:
        st.plotly_chart(cvss_chart, use_container_width=True)

def render_export_section(vulnerabilities, iac_type):
    """Render export functionality"""
    st.markdown("---")
    st.subheader("📤 Export Results")
    
    col_export1, col_export2, col_export3 = st.columns(3)
    
    with col_export1:
        if st.button("📄 Export JSON Report"):
            report = export_report(vulnerabilities, iac_type)
            st.download_button(
                "⬇️ Download JSON Report",
                report,
                file_name=f"iac_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col_export2:
        if st.button("📊 Export CSV"):
            from dataclasses import asdict
            df = pd.DataFrame([asdict(v) for v in vulnerabilities])
            csv = df.to_csv(index=False)
            st.download_button(
                "⬇️ Download CSV",
                csv,
                file_name=f"iac_vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col_export3:
        if st.button("📋 Generate Summary"):
            total_vulns = len(vulnerabilities)
            severity_summary = {}
            for vuln in vulnerabilities:
                severity_summary[vuln.severity] = severity_summary.get(vuln.severity, 0) + 1
            
            summary = f"""
# IaC Security Analysis Summary

**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**IaC Platform:** {iac_type.title()}
**Total Issues Found:** {total_vulns}

## Severity Breakdown:
"""
            for severity, count in severity_summary.items():
                summary += f"- **{severity.title()}:** {count}\n"
            
            st.markdown(summary)

def render_ai_remediation_section():
    """Render AI remediation functionality"""
    st.markdown("---")
    st.subheader("🛠️ AI Remediation")
    
    if st.button("🤖 Fix with AI"):
        if hasattr(st.session_state, 'vulnerabilities') and hasattr(st.session_state, 'code_content'):
            generate_ai_fix(
                st.session_state.vulnerabilities,
                st.session_state.code_content,
                st.session_state.iac_type
            )
        else:
            st.warning("Please run analysis first before using AI remediation.")

def main():
    """Main application function"""
    # Initialize page
    init_page_config()
    load_custom_css()
    render_header()
    
    # Initialize analyzer
    analyzer = IaCSecurityAnalyzer()
    
    # Sidebar configuration
    settings = render_sidebar()
    
    # Main content
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("📁 Input Code")
        code_content, detected_iac_type = handle_file_input(
            settings['input_method'], 
            settings['iac_type']
        )
        
        # Update iac_type if auto-detected
        if detected_iac_type != settings['iac_type']:
            settings['iac_type'] = detected_iac_type
        
        # Display code preview
        if code_content:
            with st.expander("📖 Code Preview"):
                st.code(code_content, language=settings['iac_type'])
    
    with col2:
        st.subheader("🔍 Analysis Results")
        
        if code_content and st.button("🚀 Analyze Security", type="primary"):
            with st.spinner("Analyzing code for security vulnerabilities..."):
                vulnerabilities = analyzer.analyze_code(code_content, settings['iac_type'])
                
                # Filter vulnerabilities based on settings
                if not settings['show_low_severity']:
                    vulnerabilities = [v for v in vulnerabilities if v.severity != 'low']
                
                # Store results in session state
                st.session_state.vulnerabilities = vulnerabilities
                st.session_state.iac_type = settings['iac_type']
                st.session_state.code_content = code_content
        
        # Display results if available
        if hasattr(st.session_state, 'vulnerabilities'):
            vulnerabilities = st.session_state.vulnerabilities
            
            if vulnerabilities:
                render_summary_metrics(vulnerabilities)
                render_vulnerability_details(vulnerabilities, settings)
            else:
                st.success("🎉 No security issues found! Your configuration looks secure.")
    
    # Additional sections
    if hasattr(st.session_state, 'vulnerabilities') and st.session_state.vulnerabilities:
        render_analytics_section(st.session_state.vulnerabilities)
        render_export_section(st.session_state.vulnerabilities, st.session_state.iac_type)
        render_ai_remediation_section()

if __name__ == "__main__":
    main()