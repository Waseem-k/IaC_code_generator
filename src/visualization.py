"""
Visualization functions for security analysis results
"""
import plotly.express as px
import plotly.graph_objects as go
from typing import List
from src.models import SecurityVulnerability

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

def create_severity_timeline(vulnerabilities: List[SecurityVulnerability]):
    """Create a timeline view of vulnerabilities by line number"""
    if not vulnerabilities:
        return None
    
    # Group vulnerabilities by severity
    severity_data = {'critical': [], 'high': [], 'medium': [], 'low': []}
    
    for vuln in vulnerabilities:
        if vuln.line_number:
            severity_data[vuln.severity].append({
                'line': vuln.line_number,
                'title': vuln.title,
                'rule_id': vuln.rule_id
            })
    
    fig = go.Figure()
    
    colors = {
        'critical': '#e74c3c',
        'high': '#e67e22',
        'medium': '#f39c12',
        'low': '#f1c40f'
    }
    
    for severity, items in severity_data.items():
        if items:
            lines = [item['line'] for item in items]
            titles = [f"{item['rule_id']}: {item['title']}" for item in items]
            
            fig.add_trace(go.Scatter(
                x=lines,
                y=[severity] * len(lines),
                mode='markers+text',
                name=severity.title(),
                text=titles,
                textposition="top center",
                marker=dict(
                    color=colors[severity],
                    size=12,
                    symbol='diamond'
                ),
                hovertemplate='<b>%{text}</b><br>Line: %{x}<br>Severity: %{y}<extra></extra>'
            ))
    
    fig.update_layout(
        title="Vulnerabilities by Code Location",
        xaxis_title="Line Number",
        yaxis_title="Severity",
        height=400,
        showlegend=True
    )
    
    return fig