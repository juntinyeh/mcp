# AWS Well-Architected Reliability Pillar MCP Server

An MCP (Model Context Protocol) server that provides tools for assessing AWS environments against the AWS Well-Architected Framework Reliability Pillar.

## Overview

The AWS Well-Architected Reliability Pillar MCP Server provides a set of tools that help you analyze your AWS environment for reliability best practices. It integrates with AWS services like Trusted Advisor and Resilience Hub to provide comprehensive reliability assessments and recommendations.

## Features

- **Resource Discovery**: Explore AWS resources across multiple services and regions
- **Reliability Service Checks**: Verify if key reliability services are properly configured
- **Trusted Advisor Integration**: Retrieve reliability-related checks from AWS Trusted Advisor
- **Resilience Hub Integration**: Access AWS Resilience Hub assessments for applications
- **Gap Analysis**: Identify gaps between current configuration and reliability best practices
- **Comprehensive Assessment**: Analyze overall reliability posture with detailed remediation plans

## Installation

### Prerequisites

- Python 3.9 or higher
- AWS credentials configured (via environment variables, AWS CLI, or IAM role)
- AWS Business or Enterprise Support plan (for full Trusted Advisor functionality)

### Install from PyPI

```bash
pip install aws-wa-reliability-mcp-server
```

### Install from Source

```bash
git clone https://github.com/aws-samples/aws-wa-reliability-mcp-server.git
cd aws-wa-reliability-mcp-server
pip install -e .
```

## Usage

### Starting the Server

```bash
# Start with default settings
python -m aws_wa_reliability_mcp_server

# Start with SSE transport on a specific port
python -m aws_wa_reliability_mcp_server --sse --port 8888
```

### Using the Tools

The server provides the following tools:

1. **CheckReliabilityServices**: Verify if key reliability services are properly configured
2. **GetTrustedAdvisorChecks**: Retrieve reliability-related checks from AWS Trusted Advisor
3. **GetResilienceHubAssessments**: Access AWS Resilience Hub assessments for applications
4. **GetResourceComplianceStatus**: Check compliance of specific resources against reliability best practices
5. **ExploreAwsResources**: Explore AWS resources across multiple services and regions
6. **IdentifyReliabilityGaps**: Identify gaps between current configuration and reliability best practices
7. **AnalyzeReliabilityPosture**: Perform a comprehensive reliability assessment

See the [PROMPT_TEMPLATE.md](PROMPT_TEMPLATE.md) file for detailed examples of how to use these tools.

## Example Workflow

1. Start by exploring your AWS resources:

```python
result = await ExploreAwsResources(
    region="us-east-1",
    services=["ec2", "s3", "rds", "dynamodb", "route53", "cloudwatch", "autoscaling", "elb", "backup"]
)
```

2. Check if key reliability services are properly configured:

```python
result = await CheckReliabilityServices(
    region="us-east-1",
    services=["route53", "cloudwatch", "autoscaling", "elb", "backup"]
)
```

3. Identify reliability gaps:

```python
result = await IdentifyReliabilityGaps(
    region="us-east-1",
    services=["s3", "ec2", "rds", "dynamodb", "route53", "cloudwatch", "autoscaling", "elb", "backup"]
)
```

4. Perform a comprehensive reliability assessment:

```python
result = await AnalyzeReliabilityPosture(
    regions=["us-east-1", "us-west-2"],
    services=["s3", "ec2", "rds", "dynamodb", "route53", "cloudwatch", "autoscaling", "elb", "backup"]
)
```

## AWS Permissions

The server requires the following AWS permissions:

- `ec2:Describe*`
- `s3:List*`
- `s3:Get*`
- `rds:Describe*`
- `dynamodb:List*`
- `dynamodb:Describe*`
- `route53:List*`
- `cloudwatch:Describe*`
- `autoscaling:Describe*`
- `elasticloadbalancing:Describe*`
- `backup:List*`
- `support:DescribeTrustedAdvisorChecks`
- `support:DescribeTrustedAdvisorCheckResult`
- `resiliencehub:ListApps`
- `resiliencehub:DescribeApp`
- `resiliencehub:ListAppAssessments`
- `resiliencehub:DescribeAppAssessment`

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/aws-samples/aws-wa-reliability-mcp-server.git
cd aws-wa-reliability-mcp-server

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Security

See [SECURITY.md](SECURITY.md) for details on how to report security issues.
