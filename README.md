# IaC_code_generator

A comprehensive security analysis tool for Infrastructure as Code (IaC) files. This application analyzes Terraform, CloudFormation, and Kubernetes configurations to identify security vulnerabilities and provides AI-powered remediation suggestions.

## 🛡️ Features

- **Multi-Platform Support**: Analyze Terraform, AWS CloudFormation, and Kubernetes configurations
- **Comprehensive Security Rules**: Built-in security rules covering critical vulnerabilities
- **AI-Powered Remediation**: Get automated code fixes using Google Gemini AI
- **Interactive Visualizations**: Security metrics and vulnerability distribution charts
- **Multiple Export Formats**: JSON, CSV, and Markdown reports
- **Real-time Analysis**: Upload files or paste code for immediate analysis

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key (for AI remediation features)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Waseem-k/IaC_code_generator
cd IaC_code_generator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API keys:
   - Copy `app_config.properties.example` to `app_config.properties`
   - Add your Google Gemini API key:
```properties
GEMINI_API_KEY=your_api_key_here
```

### Running the Application

```bash
streamlit run main.py
```

The application will be available at `http://localhost:8501`

## 📁 Project Structure

```
iac-security-analyzer/
├── main.py                    # Main application entry point
├── src/
│   ├── __init__.py
│   ├── analyzer.py            # Core security analyzer
│   ├── models.py              # Data models
│   ├── security_rules.py      # Security rules configuration
│   ├── visualization.py       # Chart generation
│   ├── report_generator.py    # Report generation
│   ├── ai_remediation.py      # AI-powered fixes
│   └── config.py              # Configuration management
├── requirements.txt           # Python dependencies
├── app_config.properties      # Configuration file
└── README.md                  # This file
```

## 🔍 Supported Platforms

### Terraform
- Public S3 bucket configurations
- Unencrypted EBS volumes
- Open security groups
- Unencrypted RDS instances
- IAM policies with wildcard actions

### AWS CloudFormation
- Public S3 bucket access
- Open security groups
- Missing encryption configurations

### Kubernetes
- Containers running as root
- Privileged containers
- Missing resource limits
- Security context issues

## 📊 Security Analysis

The tool analyzes your IaC files and categorizes findings by:

- **Severity**: Critical, High, Medium, Low
- **Category**: Data Protection, Network Security, Container Security, etc.
- **CVSS Score**: Common Vulnerability Scoring System ratings
- **CWE Classification**: Common Weakness Enumeration mapping

## 🤖 AI-Powered Remediation

Using Google Gemini AI, the tool can:
- Generate secure code fixes
- Explain security improvements
- Maintain code functionality while improving security posture
- Provide detailed remediation guidance

## 📈 Visualizations

- **Severity Distribution**: Pie chart showing vulnerability breakdown
- **Category Analysis**: Bar chart of security categories
- **CVSS Score Distribution**: Histogram of vulnerability scores
- **Timeline View**: Vulnerabilities by code location

## 📤 Export Options

- **JSON Report**: Comprehensive machine-readable format
- **CSV Export**: Spreadsheet-compatible vulnerability data
- **Markdown Report**: Human-readable security analysis
- **Remediation Checklist**: Actionable task list

## 🛠️ Configuration

Configure the application using `app_config.properties`:

```properties
# API Keys
GEMINI_API_KEY=your_gemini_api_key_here

# Application Settings
MAX_FILE_SIZE_MB=10
ENABLE_ADVANCED_RULES=false
DEFAULT_IAC_TYPE=terraform
```

## 🔧 Development

### Adding New Security Rules

1. Define rules in `src/security_rules.py`
2. Implement analysis logic in `src/analyzer.py`
3. Add tests for new functionality

### Extending Platform Support

1. Add platform rules to `security_rules.py`
2. Update file type detection in `main.py`
3. Add platform-specific analysis methods

## 🚨 Security Rules Reference

### Terraform Rules
- **TF001**: Public S3 Bucket
- **TF002**: Unencrypted EBS Volume
- **TF003**: Open Security Group
- **TF004**: Unencrypted RDS Instance
- **TF005**: IAM Policy with Wildcards

### CloudFormation Rules
- **CF001**: Public S3 Bucket Access
- **CF002**: Open Security Group

### Kubernetes Rules
- **K8S001**: Container Running as Root
- **K8S002**: Privileged Container
- **K8S003**: Missing Resource Limits

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Powered by [Google Gemini AI](https://ai.google.dev/)
- Visualizations by [Plotly](https://plotly.com/)