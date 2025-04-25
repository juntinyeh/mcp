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

"""Remediation generator for security findings."""

import re
import json
from typing import Dict, List, Any, Optional, Set, Literal
from loguru import logger
from pydantic import BaseModel, Field

class CommandInfo(BaseModel):
    """Information about a remediation command."""
    
    command: str = Field(..., description="The AWS CLI command to execute")
    description: str = Field(..., description="Human-readable description of what the command does")
    service: str = Field(..., description="AWS service the command applies to")
    region: str = Field(..., description="AWS region the command should be executed in")


class DryRunEffects(BaseModel):
    """Analysis of potential effects of a remediation command."""
    
    changes: List[str] = Field(default_factory=list, description="Changes that will be made")
    affected_resources: List[str] = Field(default_factory=list, description="Resources that will be affected")
    permissions_needed: List[str] = Field(default_factory=list, description="IAM permissions needed to execute")
    possible_side_effects: List[str] = Field(default_factory=list, description="Potential side effects")
    execution_time_estimate: str = Field("< 1 minute", description="Estimated execution time")
    reversible: bool = Field(True, description="Whether the change can be easily reversed")
    verification_command: Optional[str] = Field(None, description="Command to verify the change")


class RemediationItem(BaseModel):
    """A remediation action for a security finding."""
    
    finding: Dict[str, Any] = Field(..., description="The security finding that needs remediation")
    command_info: CommandInfo = Field(..., description="Command information for remediation")
    region: str = Field(..., description="AWS region where the finding was detected")
    service: str = Field(..., description="AWS service the finding relates to")
    resource_type: str = Field(..., description="Type of resource with the finding")
    dry_run_effects: Optional[DryRunEffects] = Field(None, description="Analysis of command effects")


class RemediationPlan(BaseModel):
    """Complete remediation plan for security findings."""
    
    remediation_by_severity: Dict[Literal["critical", "high", "medium", "low"], List[RemediationItem]] = Field(
        default_factory=lambda: {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        },
        description="Remediation items organized by severity"
    )
    remediation_items: List[RemediationItem] = Field(
        default_factory=list,
        description="All remediation items"
    )
    total_findings: int = Field(0, description="Total number of findings with remediation")
    has_dry_run_analysis: bool = Field(False, description="Whether dry run analysis was performed")


class RemediationGenerator:
    """Generates remediation commands for security findings with dry run analysis.
    
    This class analyzes security findings and generates appropriate AWS CLI commands
    to remediate the issues. It can also perform dry run analysis to predict the
    effects of remediation commands before they are executed.
    
    Attributes:
        session: A boto3 session for AWS API calls
        command_cache: Cache of dry run analysis results
    """
    
    def __init__(self, session=None):
        """Initialize with optional boto3 session"""
        self.session = session
        self.command_cache = {}  # Cache for dry run results
        
    async def generate_remediation_plan(self, findings: Dict, with_dry_run: bool = True) -> Dict:
        """Generate remediation plan for security findings.
        
        Creates a comprehensive remediation plan for security findings, including
        commands to execute and analysis of their potential effects. The plan is
        organized by severity to help prioritize remediation efforts.
        
        Args:
            findings: Security findings by region, service, and resource
            with_dry_run: Whether to include dry run analysis of commands
            
        Returns:
            Remediation plan with commands and effects organized by severity
            
        Example:
            ```python
            remediation_plan = await generator.generate_remediation_plan(findings)
            # Critical findings first
            critical_items = remediation_plan["remediation_by_severity"]["critical"]
            for item in critical_items:
                print(f"Command to execute: {item.command_info.command}")
            ```
        """
        remediation_items = []
        
        # Process each region
        for region, region_findings in findings.items():
            # Process each service
            for service_name, service_findings in region_findings.items():
                # Generate remediation for this service
                service_remediation = await self._generate_service_remediation(
                    service_name, service_findings, region, with_dry_run
                )
                
                # Add to remediation items
                remediation_items.extend(service_remediation)
                
        # Group by severity
        remediation_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for item in remediation_items:
            severity = item['finding'].get('severity', 'medium').lower()
            
            # Map severity to standard levels
            if severity in ['critical', 'high', 'medium', 'low']:
                remediation_by_severity[severity].append(item)
            elif 'critical' in severity:
                remediation_by_severity['critical'].append(item)
            elif 'high' in severity:
                remediation_by_severity['high'].append(item)
            elif 'medium' in severity:
                remediation_by_severity['medium'].append(item)
            else:
                remediation_by_severity['low'].append(item)
                
        # Create final remediation plan
        remediation_plan = {
            'remediation_by_severity': remediation_by_severity,
            'remediation_items': remediation_items,
            'total_findings': len(remediation_items),
            'has_dry_run_analysis': with_dry_run
        }
        
        return remediation_plan
        
    async def _generate_service_remediation(self, service_name: str, findings: Dict, region: str, with_dry_run: bool) -> List[Dict]:
        """Generate remediation for specific service findings.
        
        Creates remediation items for findings in a specific AWS service,
        including commands to execute and optionally dry run analysis.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'ec2')
            findings: Service findings organized by resource type
            region: AWS region the findings are in
            with_dry_run: Whether to include dry run analysis
            
        Returns:
            List of remediation items for the service findings
        """
        service_remediation = []
        
        # Process findings by resource type
        for resource_type, resource_findings in findings.items():
            for finding in resource_findings:
                if isinstance(finding, dict):
                    # Generate command for this finding
                    command_info = self._generate_command_for_finding(service_name, finding, region)
                    
                    if command_info:
                        remediation_item = {
                            'finding': finding,
                            'command_info': command_info,
                            'region': region,
                            'service': service_name,
                            'resource_type': resource_type
                        }
                        
                        if with_dry_run:
                            # Add dry run effects
                            dry_run_effects = await self._analyze_command_effects(
                                command_info, service_name, region
                            )
                            remediation_item['dry_run_effects'] = dry_run_effects
                            
                        service_remediation.append(remediation_item)
                        
        return service_remediation
        
    def _generate_command_for_finding(self, service_name: str, finding: Dict, region: str) -> Optional[Dict]:
        """Generate an AWS CLI command to remediate a security finding.
        
        Creates the appropriate AWS CLI command based on the service,
        finding type, and resource details. Handles common patterns for
        services like S3, EC2, and RDS.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'ec2')
            finding: Finding details with rule_id and resource_id
            region: AWS region to target
            
        Returns:
            Command information dictionary or None if no command can be generated
        """
        # Try to use pre-generated command from finding
        if 'remediation_command' in finding:
            return {
                'command': finding['remediation_command'],
                'description': finding.get('remediation', 'Apply recommended fix'),
                'service': service_name,
                'region': region
            }
            
        # Generate command based on rule ID and resource ID
        rule_id = finding.get('rule_id')
        resource_id = finding.get('resource_id')
        
        if not rule_id or not resource_id:
            return None
            
        # Service-specific command generators
        if service_name == 's3':
            if 'public_access' in rule_id:
                command = f"aws s3api put-public-access-block --bucket {resource_id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                return {
                    'command': command,
                    'description': 'Block public access to S3 bucket',
                    'service': service_name,
                    'region': region
                }
            elif 'encryption' in rule_id:
                command = f"aws s3api put-bucket-encryption --bucket {resource_id} --server-side-encryption-configuration 'Rules=[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]'"
                return {
                    'command': command,
                    'description': 'Enable default encryption for S3 bucket',
                    'service': service_name,
                    'region': region
                }
            elif 'versioning' in rule_id:
                command = f"aws s3api put-bucket-versioning --bucket {resource_id} --versioning-configuration Status=Enabled"
                return {
                    'command': command,
                    'description': 'Enable versioning for S3 bucket',
                    'service': service_name,
                    'region': region
                }
                
        elif service_name == 'ec2':
            if 'security_group' in rule_id and 'public_access' in rule_id:
                command = f"aws ec2 revoke-security-group-ingress --group-id {resource_id} --protocol all --port 0-65535 --cidr 0.0.0.0/0"
                return {
                    'command': command,
                    'description': 'Remove public access from security group',
                    'service': service_name,
                    'region': region
                }
                
        elif service_name == 'rds':
            if 'encryption' in rule_id:
                command = f"aws rds modify-db-instance --db-instance-identifier {resource_id} --storage-encrypted --apply-immediately"
                return {
                    'command': command,
                    'description': 'Enable encryption for RDS instance',
                    'service': service_name,
                    'region': region
                }
                
        # Generic command
        command = f"aws {service_name} update-{service_name.replace('_', '-')} --{resource_id}"
        return {
            'command': command,
            'description': finding.get('remediation', 'Apply recommended fix'),
            'service': service_name,
            'region': region
        }
        
    async def _analyze_command_effects(self, command_info: Dict, service_name: str, region: str) -> Dict:
        """Analyze potential effects of a remediation command.
        
        Performs a detailed analysis of what a remediation command will do
        without executing it. This includes predicting changes, affected resources,
        required permissions, possible side effects, and more.
        
        Args:
            command_info: Command information dictionary
            service_name: AWS service name
            region: AWS region
            
        Returns:
            Analysis of command effects including changes, permissions, side effects
        """
        command = command_info['command']
        description = command_info['description']
        
        # Check cache
        cache_key = f"{command}_{region}"
        if cache_key in self.command_cache:
            return self.command_cache[cache_key]
            
        # Add dry run parameter if possible
        dry_run_command = self._add_dry_run_parameter(command, service_name)
        
        # For this example, we'll simulate the effect analysis
        # In a real implementation, you would execute the dry run command
        # and analyze the result
        
        # Simulate dry run analysis
        effects = {
            'changes': self._predict_changes(command, service_name),
            'affected_resources': self._predict_affected_resources(command, service_name),
            'permissions_needed': self._predict_required_permissions(command, service_name),
            'possible_side_effects': self._predict_side_effects(command, service_name),
            'execution_time_estimate': self._estimate_execution_time(service_name),
            'reversible': self._is_reversible(command, service_name),
            'verification_command': self._generate_verification_command(command, service_name)
        }
        
        # Cache the result
        self.command_cache[cache_key] = effects
        
        return effects
        
    def _add_dry_run_parameter(self, command: str, service_name: str) -> str:
        """Add dry run parameter to an AWS CLI command.
        
        Adds the --dry-run parameter to commands for services that support it.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            Command with dry run parameter if supported, original command otherwise
        """
        # Services that support --dry-run
        dry_run_services = ['ec2', 'rds', 'elb', 'elbv2']
        
        if service_name in dry_run_services and '--dry-run' not in command:
            return f"{command} --dry-run"
            
        # Services that don't support dry run
        return command
        
    def _predict_changes(self, command: str, service_name: str) -> List[str]:
        """Predict changes that will be made by a command.
        
        Analyzes the command to determine what configuration changes
        it will make to AWS resources.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            List of human-readable changes the command will make
        """
        changes = []
        
        # Parse command to understand what it does
        if service_name == 's3':
            if 'put-public-access-block' in command:
                changes.append('Block public access to the S3 bucket')
                changes.append('Prevent public access control lists (ACLs)')
                changes.append('Block public bucket policies')
                changes.append('Restrict public bucket access')
            elif 'put-bucket-encryption' in command:
                changes.append('Enable default encryption for the S3 bucket')
                changes.append('Set AES-256 as the default encryption algorithm')
            elif 'put-bucket-versioning' in command:
                changes.append('Enable versioning for the S3 bucket')
                
        elif service_name == 'ec2':
            if 'revoke-security-group-ingress' in command:
                if '0.0.0.0/0' in command:
                    changes.append('Remove public internet access from the security group')
                else:
                    changes.append('Remove specific ingress rule from the security group')
                    
        elif service_name == 'rds':
            if 'storage-encrypted' in command:
                changes.append('Enable storage encryption for the RDS instance')
                
        # If we couldn't determine specific changes
        if not changes:
            # Extract the action from the command
            action_match = re.search(r'aws \w+ ([a-z-]+)', command)
            if action_match:
                action = action_match.group(1).replace('-', ' ')
                changes.append(f"Apply {action} operation to the {service_name} resource")
                
        return changes
        
    def _predict_affected_resources(self, command: str, service_name: str) -> List[str]:
        """Predict resources that will be affected by a command.
        
        Extracts resource identifiers from a command and determines what
        additional resources might be impacted by the change.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            List of resource identifiers and descriptions that will be affected
        """
        affected_resources = []
        
        # Try to extract resource identifier from command
        if service_name == 's3':
            # Extract bucket name
            bucket_match = re.search(r'--bucket ([^ ]+)', command)
            if bucket_match:
                bucket_name = bucket_match.group(1)
                affected_resources.append(f"S3 Bucket: {bucket_name}")
                affected_resources.append(f"Any applications using this bucket")
                
        elif service_name == 'ec2':
            # Extract security group ID
            sg_match = re.search(r'--group-id ([^ ]+)', command)
            if sg_match:
                sg_id = sg_match.group(1)
                affected_resources.append(f"Security Group: {sg_id}")
                affected_resources.append(f"EC2 instances using this security group")
                
        elif service_name == 'rds':
            # Extract DB instance ID
            db_match = re.search(r'--db-instance-identifier ([^ ]+)', command)
            if db_match:
                db_id = db_match.group(1)
                affected_resources.append(f"RDS Instance: {db_id}")
                affected_resources.append(f"Applications connecting to this database")
                
        # If we couldn't determine specific resources
        if not affected_resources:
            affected_resources.append(f"{service_name.upper()} resources targeted by the command")
            
        return affected_resources
        
    def _predict_required_permissions(self, command: str, service_name: str) -> List[str]:
        """Predict IAM permissions required to execute a command.
        
        Analyzes the command to determine what IAM permissions would be
        needed to execute it successfully.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            List of IAM permission strings (e.g., "s3:PutBucketEncryption")
        """
        # Extract action from command
        action_match = re.search(r'aws (\w+) ([a-z-]+)', command)
        if not action_match:
            return [f"{service_name}:*"]
            
        service = action_match.group(1)
        action = action_match.group(2)
        
        # Convert to IAM action format
        iam_action = action.replace('-', '')
        
        # Add required permissions
        permissions = [f"{service}:{iam_action}"]
        
        # For specific commands, add additional permissions
        if service == 's3api' and action == 'put-public-access-block':
            permissions.append("s3:PutBucketPublicAccessBlock")
        elif service == 's3api' and action == 'put-bucket-encryption':
            permissions.append("s3:PutEncryptionConfiguration")
        elif service == 'ec2' and action == 'revoke-security-group-ingress':
            permissions.append("ec2:DescribeSecurityGroups")
            
        return permissions
        
    def _predict_side_effects(self, command: str, service_name: str) -> List[str]:
        """Predict possible side effects of executing a command.
        
        Identifies potential implications and unintended consequences
        of applying the security remediation.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            List of possible side effects described in human-readable form
        """
        side_effects = []
        
        # Specific side effects for common commands
        if service_name == 's3':
            if 'put-public-access-block' in command:
                side_effects.append("Public URLs to objects in this bucket will no longer work")
                side_effects.append("Applications expecting public access will fail")
                side_effects.append("CloudFront distributions using public bucket access may need updating")
            elif 'put-bucket-encryption' in command:
                side_effects.append("Older applications may need to be updated to handle encrypted data")
                side_effects.append("Slight performance impact due to encryption/decryption overhead")
                
        elif service_name == 'ec2':
            if 'revoke-security-group-ingress' in command:
                side_effects.append("Applications dependent on these network paths will lose connectivity")
                side_effects.append("External services may not be able to reach the instances")
                
        elif service_name == 'rds':
            if 'storage-encrypted' in command:
                side_effects.append("Database instance will need to be rebooted")
                side_effects.append("Brief downtime during encryption setup")
                side_effects.append("Snapshots from unencrypted instance cannot be restored to encrypted instance")
                
        # General side effect
        if not side_effects:
            side_effects.append("No significant side effects anticipated")
            
        return side_effects
        
    def _estimate_execution_time(self, service_name: str) -> str:
        """Estimate execution time for a command.
        
        Provides an estimate of how long the remediation action will take
        to complete, based on the service type and typical API response times.
        
        Args:
            service_name: AWS service name
            
        Returns:
            Human-readable time estimate (e.g., "< 5 seconds", "5-10 minutes")
        """
        # Service-specific estimates
        if service_name == 's3':
            return "< 5 seconds"
        elif service_name == 'ec2':
            return "< 5 seconds"
        elif service_name == 'rds':
            return "5-10 minutes (requires reboot)"
        elif service_name == 'cloudfront':
            return "15-30 minutes (distribution update)"
        
        # Default estimate
        return "< 1 minute"
        
    def _is_reversible(self, command: str, service_name: str) -> bool:
        """Determine if a command is easily reversible.
        
        Analyzes whether the changes made by a command can be easily
        undone if needed.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            True if the command is easily reversible, False otherwise
        """
        # Most AWS configuration changes are reversible
        # Some specific cases might not be
        
        if service_name == 'rds' and 'delete' in command:
            return False
        elif service_name == 's3' and 'delete' in command:
            return False
        elif service_name == 'ec2' and 'terminate-instances' in command:
            return False
            
        # Default to true - most commands are configuration changes
        return True
        
    def _generate_verification_command(self, command: str, service_name: str) -> Optional[str]:
        """Generate a command to verify remediation was successful.
        
        Creates an AWS CLI command that can be used to check if the
        remediation was successfully applied.
        
        Args:
            command: AWS CLI command
            service_name: AWS service name
            
        Returns:
            Verification command as string, or None if no verification is possible
        """
        # Replace action verbs with describe/get/list
        if service_name == 's3':
            if 'put-public-access-block' in command:
                # Extract bucket name
                bucket_match = re.search(r'--bucket ([^ ]+)', command)
                if bucket_match:
                    bucket_name = bucket_match.group(1)
                    return f"aws s3api get-public-access-block --bucket {bucket_name}"
            elif 'put-bucket-encryption' in command:
                bucket_match = re.search(r'--bucket ([^ ]+)', command)
                if bucket_match:
                    bucket_name = bucket_match.group(1)
                    return f"aws s3api get-bucket-encryption --bucket {bucket_name}"
            elif 'put-bucket-versioning' in command:
                bucket_match = re.search(r'--bucket ([^ ]+)', command)
                if bucket_match:
                    bucket_name = bucket_match.group(1)
                    return f"aws s3api get-bucket-versioning --bucket {bucket_name}"
                    
        elif service_name == 'ec2':
            if 'revoke-security-group-ingress' in command:
                sg_match = re.search(r'--group-id ([^ ]+)', command)
                if sg_match:
                    sg_id = sg_match.group(1)
                    return f"aws ec2 describe-security-groups --group-ids {sg_id}"
                    
        elif service_name == 'rds':
            if 'modify-db-instance' in command:
                db_match = re.search(r'--db-instance-identifier ([^ ]+)', command)
                if db_match:
                    db_id = db_match.group(1)
                    return f"aws rds describe-db-instances --db-instance-identifier {db_id}"
                    
        # Generic verification command
        action_match = re.search(r'aws (\w+) ([a-z-]+)', command)
        if action_match:
            service = action_match.group(1)
            action = action_match.group(2)
            
            # Convert action to verification action
            if action.startswith('put-'):
                verify_action = action.replace('put-', 'get-')
                return f"aws {service} {verify_action}"
            elif action.startswith('update-'):
                verify_action = action.replace('update-', 'describe-')
                return f"aws {service} {verify_action}"
            elif action.startswith('create-'):
                verify_action = action.replace('create-', 'describe-')
                return f"aws {service} {verify_action}"
                
        return None
