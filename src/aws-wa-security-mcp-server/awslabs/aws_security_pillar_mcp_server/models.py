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

"""Data models for AWS Security Pillar MCP Server."""

from enum import Enum
from typing import Dict, List, Optional, Any, Literal, Union, Set
from pydantic import BaseModel, Field, field_validator


class SecuritySeverity(str, Enum):
    """Security finding severity levels."""
    
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFORMATIONAL = 'informational'


class SecurityDomain(str, Enum):
    """Well-Architected Framework security domains."""
    
    IDENTITY_AND_ACCESS_MANAGEMENT = 'identity_and_access_management'
    DETECTION = 'detection'
    INFRASTRUCTURE_PROTECTION = 'infrastructure_protection'
    DATA_PROTECTION = 'data_protection'
    INCIDENT_RESPONSE = 'incident_response'
    APPLICATION_SECURITY = 'application_security'


class AccessAnalyzerResponse(BaseModel):
    """Response from IAM Access Analyzer check."""
    
    enabled: bool = Field(
        ...,
        description="Whether Access Analyzer is enabled in the specified region"
    )
    analyzers: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of configured analyzers if enabled"
    )
    setup_instructions: Optional[str] = Field(
        None,
        description="Instructions for enabling Access Analyzer if not enabled"
    )
    error: Optional[str] = Field(
        None,
        description="Error message if the check failed"
    )
    message: str = Field(
        ...,
        description="Summary message about the current state"
    )


class SecurityFinding(BaseModel):
    """Security finding from an AWS resource assessment."""
    
    resource_id: str = Field(
        ...,
        description="Identifier of the resource with the finding"
    )
    rule_id: str = Field(
        ...,
        description="Identifier of the security rule that was violated"
    )
    severity: SecuritySeverity = Field(
        SecuritySeverity.MEDIUM,
        description="Severity of the finding"
    )
    description: str = Field(
        ...,
        description="Description of the finding"
    )
    remediation: Optional[str] = Field(
        None,
        description="Instructions for remediating the finding"
    )
    remediation_command: Optional[str] = Field(
        None,
        description="AWS CLI command to remediate the finding"
    )
    service: str = Field(
        ...,
        description="AWS service the resource belongs to"
    )
    region: str = Field(
        ...,
        description="AWS region the resource is in"
    )
    wa_domain: SecurityDomain = Field(
        ...,
        description="Well-Architected Framework security domain"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional details about the finding"
    )


class SecurityAssessmentReport(BaseModel):
    """Comprehensive security assessment report."""
    
    findings_by_severity: Dict[str, List[SecurityFinding]] = Field(
        default_factory=lambda: {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "informational": []
        },
        description="Security findings grouped by severity"
    )
    findings_by_service: Dict[str, List[SecurityFinding]] = Field(
        default_factory=dict,
        description="Security findings grouped by AWS service"
    )
    findings_by_domain: Dict[str, List[SecurityFinding]] = Field(
        default_factory=dict,
        description="Security findings grouped by Well-Architected domain"
    )
    regions_scanned: List[str] = Field(
        default_factory=list,
        description="AWS regions that were scanned"
    )
    services_scanned: List[str] = Field(
        default_factory=list,
        description="AWS services that were scanned"
    )
    summary_statistics: Dict[str, int] = Field(
        default_factory=dict,
        description="Summary statistics about the assessment"
    )
    timestamp: str = Field(
        ...,
        description="Timestamp when the assessment was completed"
    )


class RemediationCommand(BaseModel):
    """AWS CLI command for remediation."""
    
    command: str = Field(
        ...,
        description="AWS CLI command to execute"
    )
    description: str = Field(
        ...,
        description="Human-readable description of what the command does"
    )
    service: str = Field(
        ...,
        description="AWS service the command applies to"
    )
    region: str = Field(
        ...,
        description="AWS region the command should be executed in"
    )


class CommandEffect(BaseModel):
    """Analysis of potential effects of a remediation command."""
    
    changes: List[str] = Field(
        default_factory=list,
        description="Changes that will be made"
    )
    affected_resources: List[str] = Field(
        default_factory=list,
        description="Resources that will be affected"
    )
    permissions_needed: List[str] = Field(
        default_factory=list,
        description="IAM permissions needed to execute"
    )
    possible_side_effects: List[str] = Field(
        default_factory=list,
        description="Potential side effects"
    )
    execution_time_estimate: str = Field(
        "< 1 minute",
        description="Estimated execution time"
    )
    reversible: bool = Field(
        True,
        description="Whether the change can be easily reversed"
    )
    verification_command: Optional[str] = Field(
        None,
        description="Command to verify the change"
    )


class RemediationAction(BaseModel):
    """Remediation action for a security finding."""
    
    finding: SecurityFinding = Field(
        ...,
        description="The security finding that needs remediation"
    )
    command: RemediationCommand = Field(
        ...,
        description="Command information for remediation"
    )
    dry_run_effects: Optional[CommandEffect] = Field(
        None,
        description="Analysis of command effects"
    )


class SecurityPostureResponse(BaseModel):
    """Response from analyzing security posture."""
    
    security_assessment: SecurityAssessmentReport = Field(
        ...,
        description="Detailed security findings and recommendations"
    )
    remediation_plan: Dict[str, Any] = Field(
        ...,
        description="Actionable steps to improve security posture"
    )
    resources_analyzed: int = Field(
        0,
        description="Count of AWS resources analyzed"
    )
    findings_count: int = Field(
        0,
        description="Total number of security findings"
    )


class AwsResourceTag(BaseModel):
    """Tag associated with an AWS resource."""
    
    key: str = Field(
        ..., 
        description="The tag key"
    )
    value: str = Field(
        ..., 
        description="The tag value"
    )


class ResourceInventorySummary(BaseModel):
    """Summary of AWS resource inventory."""
    
    total_regions: int = Field(
        0,
        description="Number of AWS regions scanned"
    )
    total_services: int = Field(
        0,
        description="Number of AWS services scanned"
    )
    total_resources: int = Field(
        0,
        description="Total number of resources discovered"
    )
    resource_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of resources by resource type"
    )
    resources_by_region: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Resource counts organized by region"
    )
    resources_by_service: Dict[str, int] = Field(
        default_factory=dict,
        description="Resource counts organized by service"
    )


class AwsEc2Instance(BaseModel):
    """EC2 instance resource model."""
    
    id: str = Field(..., description="EC2 instance ID")
    type: str = Field(..., description="EC2 instance type")
    state: str = Field(..., description="Current state of the instance")
    private_ip: Optional[str] = Field(None, description="Private IP address")
    public_ip: Optional[str] = Field(None, description="Public IP address")
    vpc_id: Optional[str] = Field(None, description="VPC ID")
    subnet_id: Optional[str] = Field(None, description="Subnet ID")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class AwsS3Bucket(BaseModel):
    """S3 bucket resource model."""
    
    name: str = Field(..., description="Bucket name")
    creation_date: str = Field(..., description="Creation date")
    region: str = Field(..., description="Region the bucket is in")


class AwsVpc(BaseModel):
    """VPC resource model."""
    
    id: str = Field(..., description="VPC ID")
    cidr_block: str = Field(..., description="CIDR block")
    state: str = Field(..., description="VPC state")
    is_default: bool = Field(..., description="Whether this is the default VPC")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class AwsSecurityGroup(BaseModel):
    """Security group resource model."""
    
    id: str = Field(..., description="Security group ID")
    name: str = Field(..., description="Security group name")
    description: str = Field(..., description="Security group description")
    vpc_id: str = Field(..., description="VPC ID")
    ingress_rules: List[Dict[str, Any]] = Field(..., description="Inbound rules")
    egress_rules: List[Dict[str, Any]] = Field(..., description="Outbound rules")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class AwsRdsInstance(BaseModel):
    """RDS instance resource model."""
    
    id: str = Field(..., description="RDS instance identifier")
    engine: str = Field(..., description="Database engine")
    status: str = Field(..., description="Current status")
    storage: int = Field(..., description="Allocated storage in GB")
    endpoint: Optional[str] = Field(None, description="Database endpoint")
    vpc_id: Optional[str] = Field(None, description="VPC ID")
    multi_az: bool = Field(..., description="Multi-AZ deployment")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class AwsLambdaFunction(BaseModel):
    """Lambda function resource model."""
    
    name: str = Field(..., description="Function name")
    arn: str = Field(..., description="Function ARN")
    runtime: str = Field(..., description="Runtime environment")
    handler: str = Field(..., description="Function handler")
    role: str = Field(..., description="IAM role ARN")
    memory: int = Field(..., description="Memory size in MB")
    timeout: int = Field(..., description="Timeout in seconds")
    last_modified: str = Field(..., description="Last modified timestamp")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class TaggedResource(BaseModel):
    """Resource with tags from ResourceGroupsTaggingAPI."""
    
    arn: str = Field(..., description="Resource ARN")
    service: str = Field(..., description="AWS service")
    resource_type: str = Field(..., description="Resource type")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class ResourceComplianceStatus(BaseModel):
    """Compliance status for a resource."""
    
    resource_id: str = Field(..., description="Resource identifier")
    type: str = Field(..., description="Resource type")
    arn: Optional[str] = Field(None, description="Resource ARN")
    compliance_status: str = Field(..., description="Compliance status (COMPLIANT, NON_COMPLIANT, UNKNOWN, ERROR)")
    message: Optional[str] = Field(None, description="Additional message about the compliance status")
    configuration: Optional[Dict[str, Any]] = Field(None, description="Resource configuration")
    compliance_by_rule: Optional[Dict[str, Any]] = Field(None, description="Compliance details per rule")
    last_updated: Optional[str] = Field(None, description="Last updated timestamp")


class ResourceExplorationResponse(BaseModel):
    """Response from AWS resource exploration."""
    
    region: str = Field(
        ..., 
        description="AWS region that was explored"
    )
    services_explored: List[str] = Field(
        ...,
        description="AWS services that were explored"
    )
    resources: Dict[str, Dict[str, List[Dict[str, Any]]]] = Field(
        default_factory=dict,
        description="Resource details organized by service and resource type"
    )
    summary: Optional[Dict[str, Any]] = Field(
        None,
        description="Resource inventory summary"
    )
    tagged_resources: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Resources matching specified tags"
    )
