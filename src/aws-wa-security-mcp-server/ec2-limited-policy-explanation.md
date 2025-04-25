# EC2 Limited Policy Explanation

This document explains the permissions granted in the EC2-Limited-Policy and why they are necessary.

## Systems Manager (SSM) Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "ssm:DescribeAssociation",
    "ssm:GetDeployablePatchSnapshotForInstance",
    "ssm:GetDocument",
    "ssm:DescribeDocument",
    "ssm:GetManifest",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:ListAssociations",
    "ssm:ListInstanceAssociations",
    "ssm:PutInventory",
    "ssm:PutComplianceItems",
    "ssm:PutConfigurePackageResult",
    "ssm:UpdateAssociationStatus",
    "ssm:UpdateInstanceAssociationStatus",
    "ssm:UpdateInstanceInformation"
  ],
  "Resource": "*"
}
```

**Purpose**: These permissions allow AWS Systems Manager to manage the EC2 instance, including patching, running commands, and maintaining inventory.

## SSM Messages Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "ssmmessages:CreateControlChannel",
    "ssmmessages:CreateDataChannel",
    "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel"
  ],
  "Resource": "*"
}
```

**Purpose**: These permissions enable the SSM agent on the EC2 instance to communicate with the Systems Manager service.

## EC2 Messages Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2messages:AcknowledgeMessage",
    "ec2messages:DeleteMessage",
    "ec2messages:FailMessage",
    "ec2messages:GetEndpoint",
    "ec2messages:GetMessages",
    "ec2messages:SendReply"
  ],
  "Resource": "*"
}
```

**Purpose**: These permissions allow the EC2 instance to communicate with the EC2 service for operations like SSM Session Manager.

## S3 Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:ListBucket",
    "s3:PutObject"
  ],
  "Resource": [
    "arn:aws:s3:::your-specific-bucket-name/*",
    "arn:aws:s3:::your-specific-bucket-name"
  ]
}
```

**Purpose**: These permissions allow the EC2 instance to read from and write to a specific S3 bucket. You should replace `your-specific-bucket-name` with the actual bucket name that the instance needs to access.

## CloudWatch Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudwatch:PutMetricData",
    "cloudwatch:GetMetricStatistics",
    "cloudwatch:ListMetrics"
  ],
  "Resource": "*"
}
```

**Purpose**: These permissions allow the EC2 instance to publish metrics to CloudWatch and retrieve metric data.

## CloudWatch Logs Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:PutLogEvents"
  ],
  "Resource": "arn:aws:logs:*:*:log-group:/aws/ec2/myec2:*"
}
```

**Purpose**: These permissions allow the EC2 instance to create and write to CloudWatch Logs, but only to log groups that start with `/aws/ec2/myec2`.

## How This Policy Follows Least Privilege

1. **Specific Actions**: Only the necessary actions are allowed, not wildcard permissions
2. **Resource Restrictions**: Where possible, resources are restricted (e.g., S3 buckets, log groups)
3. **No Administrative Access**: No permissions to modify IAM, create resources, or access sensitive services
4. **Limited Scope**: Permissions are focused on the core functionality needed by an EC2 instance

## Next Steps

1. **Customize S3 Bucket Names**: Replace `your-specific-bucket-name` with actual bucket names needed
2. **Add Service-Specific Permissions**: If the instance needs to interact with other AWS services, add only the specific permissions needed
3. **Regular Review**: Periodically review CloudTrail logs to identify any permission errors and adjust the policy as needed
