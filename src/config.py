"""
Configuration management for the IaC Security Policy Generator
"""
import os
from typing import Dict, Any
from jproperties import Properties

def load_config(config_file: str = 'app_config.properties') -> Dict[str, Any]:
    """Load configuration from properties file with fallback to environment variables"""
    config = {}
    
    # Try to load from properties file
    if os.path.exists(config_file):
        configs = Properties()
        with open(config_file, 'rb') as f:
            configs.load(f)
        
        # Extract configuration values
        gemini_api_key = configs.get("GEMINI_API_KEY")
        if gemini_api_key:
            config['gemini_api_key'] = gemini_api_key.data
    
    # Fallback to environment variables
    if 'gemini_api_key' not in config:
        config['gemini_api_key'] = os.getenv('GEMINI_API_KEY')
    
    # Add other default configurations
    config.update({
        'app_name': 'IaC Security Policy Generator',
        'version': '1.0.0',
        'max_file_size_mb': 10,
        'supported_file_types': ['.tf', '.json', '.yaml', '.yml'],
        'default_iac_type': 'terraform',
        'enable_advanced_rules': False,
        'max_vulnerabilities_display': 100
    })
    
    return config

def get_app_metadata() -> Dict[str, str]:
    """Get application metadata"""
    return {
        'name': 'IaC Security Policy Generator',
        'version': '1.0.0',
        'description': 'Analyze Infrastructure as Code files for security vulnerabilities and fix with AI assistance.',
        'author': 'Waseem Khan',
        'license': 'MIT',
        'repository': 'https://github.com/Waseem-k/IaC_code_generator'
    }

def get_supported_platforms() -> Dict[str, Dict[str, Any]]:
    """Get supported IaC platforms configuration"""
    return {
        'terraform': {
            'name': 'Terraform',
            'extensions': ['.tf'],
            'description': 'HashiCorp Terraform configuration files',
            'icon': '🏗️'
        },
        'cloudformation': {
            'name': 'AWS CloudFormation',
            'extensions': ['.json', '.yaml', '.yml'],
            'description': 'AWS CloudFormation templates',
            'icon': '☁️'
        },
        'kubernetes': {
            'name': 'Kubernetes',
            'extensions': ['.yaml', '.yml'],
            'description': 'Kubernetes YAML manifests',
            'icon': '🚢'
        }
    }

def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration settings"""
    required_keys = ['gemini_api_key']
    
    for key in required_keys:
        if not config.get(key):
            return False
    
    return True