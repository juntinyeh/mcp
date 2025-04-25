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

"""Gap analyzer for AWS security findings."""

from typing import Dict, List, Any, Optional, Set
from loguru import logger
from pydantic import BaseModel, Field

class ResourceGap(BaseModel):
    """Resource that needs additional security scanning."""
    
    resource_id: str = Field(..., description="Resource identifier")
    resource_type: str = Field(..., description="Resource type")
    resource_details: Dict[str, Any] = Field(default_factory=dict, description="Resource details")
    service: str = Field(..., description="AWS service the resource belongs to")
    region: str = Field(..., description="AWS region the resource is in")


class GapAnalysisResult(BaseModel):
    """Result of gap analysis between security findings and discovered resources."""
    
    gaps_by_region: Dict[str, Dict[str, Dict[str, List[Dict]]]] = Field(
        default_factory=dict, 
        description="Gaps organized by region, service, and resource type"
    )
    total_resources: int = Field(0, description="Total number of resources analyzed")
    resources_with_findings: int = Field(0, description="Resources that have existing findings")
    resources_needing_scanning: int = Field(0, description="Resources that need custom scanning")


class GapAnalyzer:
    """Identifies gaps between AWS security service findings and discovered resources.
    
    This class analyzes resources discovered in an AWS environment and compares them
    against existing security findings to identify resources that need additional
    security scanning or assessment.
    """
    
    async def analyze_gaps(self, native_findings: Dict, discovered_resources: Dict) -> Dict:
        """Identify resources not covered by security services.
        
        Analyzes the gap between resources discovered through direct API calls
        and resources that already have findings from AWS security services.
        Resources without existing findings are identified for custom scanning.
        
        Args:
            native_findings: Findings from AWS security services organized by region and service
            discovered_resources: Resources discovered by scanner organized by region and service
            
        Returns:
            Dictionary of resources that need custom scanning, organized by region and service
        """
        gaps = {}
        
        # Process each region
        for region, region_resources in discovered_resources.items():
            region_findings = native_findings.get(region, {})
            region_gaps = {}
            
            # Process each service in the region
            for service_name, service_resources in region_resources.items():
                service_findings = region_findings.get(service_name, {})
                service_gaps = self._identify_service_gaps(service_name, service_resources, service_findings)
                
                if service_gaps:
                    region_gaps[service_name] = service_gaps
                    
            if region_gaps:
                gaps[region] = region_gaps
                
        return gaps
        
    def _identify_service_gaps(self, service_name: str, resources: Dict, findings: Dict) -> Dict:
        """Identify resources that need custom scanning for a service.
        
        Compares discovered resources against existing findings for a specific
        AWS service to identify resources that require additional security scanning.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'ec2', 'rds')
            resources: Discovered resources for the service grouped by resource type
            findings: Native findings for the service from AWS security services
            
        Returns:
            Dictionary of resources that need custom scanning grouped by resource type
        """
        # Special handling for specific services
        if service_name == 'securityhub':
            return {}  # Security Hub doesn't have resources to scan
        elif service_name == 'guardduty':
            return {}  # GuardDuty doesn't have resources to scan
        
        # Extract resource identifiers from findings
        finding_resource_ids = self._extract_resource_ids_from_findings(findings)
        
        # Find resources without findings
        gaps = {}
        for resource_type, type_resources in resources.items():
            if not isinstance(type_resources, list):
                continue
                
            uncovered_resources = []
            
            for resource in type_resources:
                if not isinstance(resource, dict):
                    continue
                    
                resource_id = self._extract_resource_id(resource)
                
                # Skip resources that have findings
                if resource_id and resource_id in finding_resource_ids:
                    continue
                    
                uncovered_resources.append(resource)
                
            if uncovered_resources:
                gaps[resource_type] = uncovered_resources
                
        return gaps
        
    def _extract_resource_ids_from_findings(self, findings: Dict) -> Set[str]:
        """Extract resource identifiers from security findings.
        
        Processes different types of security findings to extract the resource
        identifiers they refer to, handling various finding formats from
        different AWS security services.
        
        Args:
            findings: Security findings from AWS security services organized by type
            
        Returns:
            Set of unique resource identifiers mentioned in the findings
        """
        resource_ids = set()
        
        # Extract from all_findings
        all_findings = findings.get('all_findings', [])
        for finding in all_findings:
            if isinstance(finding, dict):
                # Try to extract resource identifiers
                if 'Resources' in finding:
                    for resource in finding['Resources']:
                        if isinstance(resource, dict) and 'Id' in resource:
                            resource_ids.add(resource['Id'])
                elif 'resource' in finding:
                    resource = finding['resource']
                    if isinstance(resource, dict) and 'id' in resource:
                        resource_ids.add(resource['id'])
                elif 'ResourceArn' in finding:
                    resource_ids.add(finding['ResourceArn'])
                elif 'resourceArn' in finding:
                    resource_ids.add(finding['resourceArn'])
                elif 'resource' in finding:
                    resource_ids.add(finding['resource'])
                    
        # Extract from findings by type
        by_type = findings.get('by_type', {})
        for finding_type, type_findings in by_type.items():
            for finding in type_findings:
                if isinstance(finding, dict):
                    if 'ResourceArn' in finding:
                        resource_ids.add(finding['ResourceArn'])
                    elif 'resourceArn' in finding:
                        resource_ids.add(finding['resourceArn'])
                    elif 'resource' in finding:
                        resource_ids.add(finding['resource'])
                        
        # Extract from findings by severity
        by_severity = findings.get('by_severity', {})
        for severity, severity_findings in by_severity.items():
            for finding in severity_findings:
                if isinstance(finding, dict):
                    if 'ResourceArn' in finding:
                        resource_ids.add(finding['ResourceArn'])
                    elif 'resourceArn' in finding:
                        resource_ids.add(finding['resourceArn'])
                    elif 'resource' in finding:
                        resource_ids.add(finding['resource'])
                        
        # Extract from findings by resource type
        by_resource = findings.get('by_resource_type', {})
        for resource_type, resource_findings in by_resource.items():
            for finding in resource_findings:
                if isinstance(finding, dict):
                    if 'ResourceArn' in finding:
                        resource_ids.add(finding['ResourceArn'])
                    elif 'resourceArn' in finding:
                        resource_ids.add(finding['resourceArn'])
                    elif 'resource' in finding:
                        resource_ids.add(finding['resource'])
                        
        # Extract from findings by rule
        by_rule = findings.get('by_rule', {})
        for rule, rule_findings in by_rule.items():
            for finding in rule_findings:
                if isinstance(finding, dict):
                    if 'EvaluationResultIdentifier' in finding:
                        result_id = finding['EvaluationResultIdentifier']
                        if isinstance(result_id, dict) and 'EvaluationResultQualifier' in result_id:
                            qualifier = result_id['EvaluationResultQualifier']
                            if isinstance(qualifier, dict) and 'ResourceId' in qualifier:
                                resource_ids.add(qualifier['ResourceId'])
                                
        return resource_ids
        
    def _extract_resource_id(self, resource: Dict) -> Optional[str]:
        """Extract resource identifier from a resource object.
        
        Attempts to extract a unique identifier from a resource dictionary
        by checking common identifier field names across AWS services.
        
        Args:
            resource: Resource dictionary containing resource details
            
        Returns:
            Resource identifier string if found, None otherwise
        """
        # Common resource identifier properties
        id_properties = [
            'Id', 'id', 'ID',
            'Arn', 'arn', 'ARN',
            'ResourceId', 'resourceId',
            'BucketName', 'bucketName',
            'InstanceId', 'instanceId',
            'FunctionName', 'functionName',
            'TableName', 'tableName',
            'ClusterName', 'clusterName'
        ]
        
        for prop in id_properties:
            if prop in resource:
                return resource[prop]
                
        return None
