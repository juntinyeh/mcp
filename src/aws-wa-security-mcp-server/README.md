# AWS Security Pillar MCP Server

An MCP (Model Context Protocol) server that provides dynamic AWS security assessment capabilities focused on the Security Pillar of the AWS Well-Architected Framework.

## Overview

The AWS Security Pillar MCP Server automatically discovers AWS resources and evaluates them against security best practices derived from the AWS Well-Architected Framework's Security Pillar. It integrates with existing AWS security services, identifies gaps in coverage, and provides detailed remediation steps with dry run analysis.

### Key Features

- **Integration-First Approach**: Prioritizes findings from AWS security services before running custom scans
- **Dynamic Resource Discovery**: Automatically discovers AWS resources across regions and services
- **Dynamic Rule Generation**: Generates security rules based on resource properties and Well-Architected best practices
- **Gap Analysis**: Identifies resources not covered by existing security services
- **Well-Architected Documentation Integration**: Enhances security analysis with Well-Architected Framework guidance
- **Detailed Remediation**: Provides AWS CLI commands with dry run analysis to fix security issues
- **Comprehensive Reporting**: Generates detailed security assessment reports with recommendations
- **Resource Exploration**: Provides comprehensive inventory of AWS resources in your environment
- **Debug Capabilities**: Enhanced debugging with phase-by-phase timing and analysis information

## Available Tools

The server provides the following tools:

1. **CheckAccessAnalyzerStatus**: Verifies if IAM Access Analyzer is enabled and properly configured
2. **CheckSecurityHubStatus**: Checks if AWS Security Hub is enabled with security standards
3. **CheckGuardDutyStatus**: Verifies if Amazon GuardDuty threat detection service is enabled
4. **CheckInspectorStatus**: Checks if Amazon Inspector vulnerability assessment service is enabled
5. **ExploreAwsResources**: Provides comprehensive inventory of AWS resources across services
6. **GetSecurityFindings**: Retrieves security findings from AWS security services with filtering
7. **GetResourceComplianceStatus**: Checks compliance status of specific AWS resources
8. **AnalyzeSecurityPosture**: Performs a comprehensive security assessment against Well-Architected

## Installation

### Prerequisites

- Python 3.10 or higher
- AWS CLI configured with appropriate permissions
- Valid AWS credentials or AWS IAM role

### Installation via UVX

The recommended way to install the AWS Security Pillar MCP Server is using the `uvx` package manager:

```bash
uvx install awslabs.aws-security-pillar-mcp-server
```

### Manual Installation

You can also install directly from the source code:

```bash
git clone https://github.com/aws-samples/aws-security-pillar-mcp-server.git
cd aws-security-pillar-mcp-server
pip install -e .
```

## Configuration

### MCP Configuration

To use the AWS Security Pillar MCP Server with Amazon Q, add it to your MCP configuration file (typically located at `~/.aws/amazonq/mcp.json`):

```json
{
  "mcpServers": {
    "awslabs.aws-security-pillar-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.aws-security-pillar-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "your-aws-profile",
        "AWS_REGION": "us-east-1",
        "FASTMCP_LOG_LEVEL": "ERROR"
      }
    }
  }
}
```

### Environment Variables

The AWS Security Pillar MCP Server supports the following environment variables:

- `AWS_PROFILE`: AWS CLI profile to use
- `AWS_REGION`: Default AWS region to use
- `SECURITY_RULES_REPO`: GitHub repository URL for custom security rules
- `SECURITY_RULES_DIR`: Local directory path for custom security rules
- `FASTMCP_LOG_LEVEL`: Log level for the server (ERROR, WARNING, INFO, DEBUG)

## Usage

### Using with Amazon Q

To get started quickly, use the prompt templates from the `PROMPT_TEMPLATE.md` file in this repository. These templates provide ready-to-use prompts for common security assessment tasks.

### Basic Usage

1. Make sure your AWS credentials are configured properly
2. Start your MCP client (e.g., Amazon Q Developer CLI)
3. Use the `analyze_security_posture` tool to scan your AWS environment:

```
analyze_security_posture --regions us-east-1 us-west-2
```

### Step-by-Step Assessment

For a comprehensive security assessment, follow this workflow:

1. **First, check your security services**:
   ```
   check_access_analyzer_status --region us-east-1
   check_security_hub_status --region us-east-1
   check_guard_duty_status --region us-east-1
   check_inspector_status --region us-east-1
   ```

2. **Next, explore your resources**:
   ```
   explore_aws_resources --region us-east-1 --services ec2,s3,rds,lambda,iam
   ```

3. **Then, perform a comprehensive security assessment**:
   ```
   analyze_security_posture --regions us-east-1 --debug true
   ```

4. **Finally, review specific findings for critical services**:
   ```
   get_security_findings --region us-east-1 --service guardduty --severity HIGH
   ```

### Advanced Options

#### Resource Exploration

To get a comprehensive inventory of your AWS resources:

```
explore_aws_resources --region us-east-1 --services ec2,s3,rds,lambda,iam --include_summary true --search_tag_key Environment
```

#### Security Findings Retrieval

To retrieve security findings from AWS security services:

```
get_security_findings --region us-east-1 --service securityhub --max_findings 50 --severity HIGH
```

#### Resource Compliance Checking

To check the compliance status of a specific resource:

```
get_resource_compliance --region us-east-1 --resource_id i-1234567890abcdef0 --resource_type ec2-instance
```

## Extending the Server

### Custom Security Rules

You can extend the server with custom security rules in two ways:

1. **GitHub Repository**: Set the `SECURITY_RULES_REPO` environment variable to a GitHub repository URL
2. **Local Directory**: Set the `SECURITY_RULES_DIR` environment variable to a local directory path

### Using Utility Functions

Advanced users can directly import and use the utility functions in their code:

```python
from awslabs.aws_security_pillar_mcp_server import (
    check_security_hub,
    list_resources_by_service,
    get_security_findings
)

# Your custom code here
```

## Contributing

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for details on how to contribute to this project.

## License

Apache License 2.0
