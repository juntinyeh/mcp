# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
# and limitations under the License.

"""Constants for the AWS Security Pillar MCP Server."""

# Default AWS regions to use if none are specified
DEFAULT_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]

# Instructions for the MCP server
INSTRUCTIONS = """AWS Security Pillar MCP Server for analyzing AWS environments against Well-Architected Framework security principles.

This server dynamically adapts to your AWS environment, without requiring pre-defined services or rules.

## Key Capabilities
- Security services integration (Security Hub, GuardDuty, etc.)
- Dynamic resource discovery and security scanning
- Well-Architected Framework security analysis
- Detailed remediation planning with dry run analysis

## Available Tools

### CheckAccessAnalyzerStatus
Verifies if IAM Access Analyzer is enabled in a specified region and provides setup guidance if needed.

### CheckSecurityHubStatus
Checks if AWS Security Hub is enabled in a specified region and lists enabled security standards.

### CheckGuardDutyStatus
Verifies if Amazon GuardDuty threat detection service is enabled and provides setup instructions if needed.

### CheckInspectorStatus
Checks if Amazon Inspector vulnerability assessment service is enabled and shows status of scan types.

### ExploreAwsResources
Provides a comprehensive inventory of AWS resources within a specified region across multiple services.
This tool is useful for understanding what resources are deployed in your environment before conducting
a security assessment.

### GetSecurityFindings
Retrieves security findings from various AWS security services including GuardDuty, Security Hub,
Inspector, and IAM Access Analyzer with filtering options by severity.

### GetResourceComplianceStatus
Checks the compliance status of specific AWS resources against AWS Config rules, providing
detailed compliance information and configuration history.

### AnalyzeSecurityPosture
Performs a comprehensive security assessment of your AWS environment against the Well-Architected Framework.

## Usage Guidelines
1. Start by exploring your AWS resources to understand your environment:
   - Use ExploreAwsResources to get a comprehensive inventory of resources
   - Review what services and resources are deployed in your target region

2. Check if key security services are enabled:
   - Use CheckAccessAnalyzerStatus to verify IAM Access Analyzer
   - Use CheckSecurityHubStatus to verify Security Hub
   - Use CheckGuardDutyStatus to verify GuardDuty
   - Use CheckInspectorStatus to verify Amazon Inspector

3. Run a comprehensive security assessment:
   - Use AnalyzeSecurityPosture for a thorough security evaluation
   - Review the generated security assessment and remediation plan

4. Apply recommended remediation steps to improve your security posture

## AWS Security Pillar
This server aligns with the Security Pillar of the AWS Well-Architected Framework, which focuses on:
- Identity and Access Management
- Detection Controls
- Infrastructure Protection
- Data Protection
- Incident Response

For more information, see: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
"""

# Service descriptions for AWS services
SERVICE_DESCRIPTIONS = {
    "s3": "Amazon Simple Storage Service (S3) is an object storage service",
    "ec2": "Amazon Elastic Compute Cloud (EC2) provides resizable compute capacity",
    "rds": "Amazon Relational Database Service (RDS) facilitates database management",
    "iam": "AWS Identity and Access Management (IAM) controls access to AWS services",
    "lambda": "AWS Lambda is a serverless compute service",
    "cloudfront": "Amazon CloudFront is a content delivery network service",
    "route53": "Amazon Route 53 is a scalable DNS web service",
    "dynamodb": "Amazon DynamoDB is a NoSQL database service",
    "securityhub": "AWS Security Hub is a security posture management service",
    "guardduty": "Amazon GuardDuty is a threat detection service",
    "config": "AWS Config is a service for assessing, auditing, and evaluating configurations",
    "cloudtrail": "AWS CloudTrail tracks user activity and API usage",
    "inspector": "Amazon Inspector is a vulnerability management service",
    "macie": "Amazon Macie is a data security service",
    "kms": "AWS Key Management Service (KMS) creates and manages cryptographic keys",
    "waf": "AWS WAF is a web application firewall",
    "shield": "AWS Shield is a managed DDoS protection service",
    "firewall": "AWS Network Firewall is a stateful, managed network firewall service",
    "vpc": "Amazon Virtual Private Cloud (VPC) provides isolated cloud resources",
    "ebs": "Amazon Elastic Block Store (EBS) provides block-level storage volumes",
    "elb": "Elastic Load Balancing (ELB) distributes incoming traffic",
    "apigateway": "Amazon API Gateway is a fully managed service for APIs",
    "acm": "AWS Certificate Manager handles SSL/TLS certificates",
    "secretsmanager": "AWS Secrets Manager securely stores and rotates secrets",
    "ssm": "AWS Systems Manager provides visibility and control over infrastructure",
}

# Security domains from Well-Architected Framework
SECURITY_DOMAINS = [
    "identity_and_access_management",
    "detection",
    "infrastructure_protection",
    "data_protection",
    "incident_response",
    "application_security",
]

# Severity levels for security findings
SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
}
