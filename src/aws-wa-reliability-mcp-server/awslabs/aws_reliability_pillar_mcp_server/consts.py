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

"""Constants for the AWS Well-Architected Reliability Pillar MCP Server."""

# Default AWS regions to use if region listing fails
DEFAULT_REGIONS = [
    'us-east-1',
    'us-east-2',
    'us-west-1',
    'us-west-2',
    'eu-west-1',
    'eu-west-2',
    'eu-central-1',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-southeast-1',
    'ap-southeast-2',
    'ap-south-1',
    'sa-east-1',
    'ca-central-1'
]

# Service descriptions for supported AWS services
SERVICE_DESCRIPTIONS = {
    's3': 'Amazon Simple Storage Service (S3)',
    'ec2': 'Amazon Elastic Compute Cloud (EC2)',
    'rds': 'Amazon Relational Database Service (RDS)',
    'lambda': 'AWS Lambda',
    'dynamodb': 'Amazon DynamoDB',
    'route53': 'Amazon Route 53',
    'cloudwatch': 'Amazon CloudWatch',
    'autoscaling': 'AWS Auto Scaling',
    'elb': 'Elastic Load Balancing (Classic)',
    'elbv2': 'Elastic Load Balancing (Application/Network)',
    'backup': 'AWS Backup',
    'sns': 'Amazon Simple Notification Service (SNS)',
    'sqs': 'Amazon Simple Queue Service (SQS)',
    'cloudfront': 'Amazon CloudFront',
    'elasticache': 'Amazon ElastiCache',
    'apigateway': 'Amazon API Gateway',
    'kinesis': 'Amazon Kinesis',
    'efs': 'Amazon Elastic File System (EFS)',
    'kms': 'AWS Key Management Service (KMS)',
    'waf': 'AWS WAF',
    'shield': 'AWS Shield',
    'acm': 'AWS Certificate Manager (ACM)',
    'secretsmanager': 'AWS Secrets Manager',
    'ssm': 'AWS Systems Manager',
    'cloudformation': 'AWS CloudFormation',
    'vpc': 'Amazon Virtual Private Cloud (VPC)',
    'iam': 'AWS Identity and Access Management (IAM)',
    'guardduty': 'Amazon GuardDuty',
    'config': 'AWS Config',
    'cloudtrail': 'AWS CloudTrail',
    'organizations': 'AWS Organizations',
    'securityhub': 'AWS Security Hub',
    'resiliencehub': 'AWS Resilience Hub'
}

# Reliability domains from the AWS Well-Architected Framework
RELIABILITY_DOMAINS = [
    {
        'id': 'foundations',
        'name': 'Foundations',
        'description': 'Establish foundational requirements that influence reliability',
        'best_practices': [
            'REL1: How do you manage service quotas and constraints?',
            'REL2: How do you plan your network topology?'
        ]
    },
    {
        'id': 'workload_architecture',
        'name': 'Workload Architecture',
        'description': 'Design your workload service architecture for reliability',
        'best_practices': [
            'REL3: How do you design your workload service architecture?',
            'REL4: How do you design interactions in a distributed system to prevent failures?',
            'REL5: How do you design interactions in a distributed system to mitigate or withstand failures?'
        ]
    },
    {
        'id': 'change_management',
        'name': 'Change Management',
        'description': 'Manage change in an automated and predictable manner',
        'best_practices': [
            'REL6: How do you monitor workload resources?',
            'REL7: How do you design your workload to adapt to changes in demand?',
            'REL8: How do you implement change?'
        ]
    },
    {
        'id': 'failure_management',
        'name': 'Failure Management',
        'description': 'Anticipate, respond to, and prevent failures',
        'best_practices': [
            'REL9: How do you back up data?',
            'REL10: How do you use fault isolation to protect your workload?',
            'REL11: How do you design your workload to withstand component failures?',
            'REL12: How do you test reliability?',
            'REL13: How do you plan for disaster recovery?'
        ]
    }
]

# Risk levels for reliability findings
RISK_LEVELS = {
    'HIGH': 'High risk issues that require immediate attention',
    'MEDIUM': 'Medium risk issues that should be addressed soon',
    'LOW': 'Low risk issues that should be addressed as part of regular maintenance',
    'INFORMATIONAL': 'Informational findings that may not require action'
}

# Trusted Advisor categories related to reliability
TRUSTED_ADVISOR_RELIABILITY_CATEGORIES = [
    'fault_tolerance',
    'performance',
    'service_limits'
]

# Resilience Hub compliance statuses
RESILIENCE_HUB_COMPLIANCE_STATUSES = {
    'COMPLIANT': 'The application meets the resiliency policy requirements',
    'NOT_COMPLIANT': 'The application does not meet the resiliency policy requirements',
    'POLICY_VIOLATED': 'The application violates the resiliency policy',
    'NOT_ASSESSED': 'The application has not been assessed'
}

# Common reliability metrics and their descriptions
RELIABILITY_METRICS = {
    'availability': 'Percentage of time that a workload is available for use',
    'recovery_time_objective': 'Maximum acceptable time to restore a system after a failure (RTO)',
    'recovery_point_objective': 'Maximum acceptable period of data loss (RPO)',
    'mean_time_between_failures': 'Average time between system failures (MTBF)',
    'mean_time_to_recovery': 'Average time to recover from a failure (MTTR)',
    'error_rate': 'Percentage of requests that result in errors',
    'latency': 'Time taken to respond to a request',
    'throughput': 'Number of requests processed per unit time'
}

# Common reliability best practices
RELIABILITY_BEST_PRACTICES = {
    'multi_az_deployment': 'Deploy resources across multiple Availability Zones',
    'auto_scaling': 'Implement Auto Scaling for EC2 instances and other scalable resources',
    'monitoring_and_alerting': 'Set up CloudWatch alarms for key metrics',
    'backup_strategy': 'Implement AWS Backup or service-specific backup solutions',
    'disaster_recovery': 'Develop and test disaster recovery procedures',
    'service_quotas': 'Monitor and manage service quotas to prevent throttling',
    'load_balancing': 'Use Elastic Load Balancing to distribute traffic',
    'health_checks': 'Configure Route 53 health checks for DNS failover',
    'resilience_testing': 'Use AWS Fault Injection Simulator for chaos engineering'
}
