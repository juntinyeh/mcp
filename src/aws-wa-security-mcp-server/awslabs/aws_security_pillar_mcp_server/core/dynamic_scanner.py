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

"""Dynamic AWS resource scanner that adapts to any AWS environment."""

import boto3
import botocore
import inspect
import asyncio
from typing import Dict, List, Any, Set, Optional
from loguru import logger
from pydantic import BaseModel, Field

class ResourceCollection(BaseModel):
    """Collection of AWS resources grouped by type."""
    
    resource_type: str = Field(..., description="Type of AWS resource")
    resources: List[Dict[str, Any]] = Field(default_factory=list, description="List of resources of this type")


class ScanResult(BaseModel):
    """Result of scanning AWS resources in a region."""
    
    region: str = Field(..., description="AWS region that was scanned")
    services: Dict[str, Dict[str, List[Dict[str, Any]]]] = Field(
        default_factory=dict, 
        description="Resources grouped by service and resource type"
    )
    resource_count: int = Field(0, description="Total number of resources found")
    service_count: int = Field(0, description="Number of services scanned")


class DynamicScanner:
    """Fully dynamic AWS resource scanner that adapts to any AWS environment.
    
    This scanner dynamically discovers AWS services and resources without requiring
    predefined knowledge of specific service APIs. It uses introspection to find
    available API methods and automatically calls appropriate discovery methods.
    
    Attributes:
        session: A boto3 session used for AWS API calls
        available_services: List of AWS services available in the current region
        discovery_methods: Mapping of service names to available discovery methods
    """
    
    def __init__(self, session=None):
        """Initialize the scanner with an optional boto3 session"""
        self.session = session or boto3.Session()
        self.available_services = self._get_available_services()
        # Map of service-to-describe methods for resource discovery
        self.discovery_methods = self._build_discovery_methods()
        
    def _get_available_services(self) -> List[str]:
        """Get all available services from boto3.
        
        Returns:
            List of AWS service names available in the current session
        """
        return self.session.get_available_services()
    
    def _build_discovery_methods(self) -> Dict[str, List[str]]:
        """Build a map of service to discovery methods.
        
        Automatically identifies appropriate methods for resource discovery
        by examining available AWS API client methods.
        
        Returns:
            Dictionary mapping service names to lists of discovery method names
        """
        discovery_methods = {}
        
        for service_name in self.available_services:
            try:
                # Create a client for the service
                client = self.session.client(service_name, region_name='us-east-1')
                
                # Look for list_* and describe_* methods
                methods = [
                    method_name for method_name in dir(client)
                    if callable(getattr(client, method_name)) and (
                        method_name.startswith('list_') or 
                        method_name.startswith('describe_') or
                        method_name.startswith('get_')
                    )
                ]
                
                if methods:
                    discovery_methods[service_name] = methods
            except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError):
                # Skip services that can't be initialized
                pass
                
        return discovery_methods
    
    async def scan_environment(self, regions: List[str], service_filter: Optional[List[str]] = None) -> Dict:
        """Scan AWS environment dynamically across regions.
        
        Discovers AWS resources across multiple regions using available discovery methods.
        Results are organized in a nested dictionary structure for easy access.
        
        Args:
            regions: List of AWS regions to scan (e.g., ['us-east-1', 'eu-west-1'])
            service_filter: Optional list of services to limit discovery
            
        Returns:
            Dictionary of discovered resources by region, service and type
            
        Example:
            ```python
            resources = await scanner.scan_environment(['us-east-1'], ['s3', 'ec2'])
            # Access resources:
            s3_buckets = resources['us-east-1']['s3']['list_buckets']
            ```
        """
        resources = {}
        
        # Filter services if specified
        target_services = (
            [s for s in service_filter if s in self.available_services] 
            if service_filter else self.available_services
        )
        
        # For each region, scan services
        for region in regions:
            resources[region] = {}
            
            # Only scan services that have discovery methods
            services_to_scan = [
                service for service in target_services 
                if service in self.discovery_methods
            ]
            
            # Execute scans concurrently for efficiency
            scan_tasks = []
            for service_name in services_to_scan:
                task = asyncio.create_task(
                    self._scan_service(service_name, region)
                )
                scan_tasks.append((service_name, task))
                
            # Wait for all scans to complete
            for service_name, task in scan_tasks:
                try:
                    service_resources = await task
                    if service_resources:
                        resources[region][service_name] = service_resources
                except Exception as e:
                    logger.error(f"Error scanning {service_name} in {region}: {e}")
                
        return resources
    
    async def _scan_service(self, service_name: str, region: str) -> Dict:
        """Scan a specific service in a region.
        
        Executes discovery methods for a service in a specific region
        and collects the results.
        
        Args:
            service_name: AWS service name to scan
            region: AWS region to scan in
            
        Returns:
            Dictionary of resources discovered for this service
        """
        service_resources = {}
        
        try:
            # Create regional client
            client = self.session.client(service_name, region_name=region)
            
            # Get discovery methods for this service
            methods = self.discovery_methods.get(service_name, [])
            
            # Execute each discovery method
            for method_name in methods:
                try:
                    # Get the method
                    method = getattr(client, method_name)
                    
                    # Check if method has required parameters
                    sig = inspect.signature(method)
                    required_params = [
                        param for param, param_obj in sig.parameters.items() 
                        if param_obj.default is inspect.Parameter.empty and 
                        param != 'self'
                    ]
                    
                    # Skip methods with required parameters we can't provide
                    if required_params:
                        continue
                        
                    # Execute the method
                    response = method()
                    
                    # Process response to extract resources
                    resources = self._extract_resources_from_response(response)
                    
                    if resources:
                        service_resources[method_name] = resources
                except Exception as e:
                    logger.debug(f"Error executing {method_name} for {service_name}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error scanning {service_name} in {region}: {e}")
            
        return service_resources
    
    def _extract_resources_from_response(self, response: Dict) -> List[Dict]:
        """Extract resources from an AWS API response.
        
        Parses AWS API responses to extract resource information,
        handling various response formats and structures.
        
        Args:
            response: AWS API response dictionary
            
        Returns:
            List of resource dictionaries extracted from the response
        """
        if not isinstance(response, dict):
            return []
            
        # Common response patterns
        resource_keys = [
            # Common response keys that contain resources
            'Resources', 'resource', 'resources',
            'Instances', 'instances',
            'Volumes', 'volumes',
            'Buckets', 'buckets',
            'Functions', 'functions',
            'Tables', 'tables',
            'Clusters', 'clusters',
            'Distributions', 'distributions',
            'SecurityGroups', 'securityGroups',
            'Images', 'images',
            'Items', 'items',
            # AWS specific keys
            'DBInstances', 'StackResources', 'LayerVersions', 
            'Topics', 'QueueUrls', 'Rules', 'VirtualMfaDevices',
            'ConfigurationItems', 'Findings', 'MetricAlarms',
            'Trails', 'StreamNames', 'AccessPoints'
        ]
        
        # Look for these keys in the response
        for key in resource_keys:
            if key in response and isinstance(response[key], list):
                return response[key]
                
        # Look for plurals or list/array responses
        for key in response:
            # If it ends with common plural suffixes
            for suffix in ['List', 'set', 'Set', 'Array', 'array', 's']:
                if key.endswith(suffix) and isinstance(response[key], list):
                    return response[key]
                    
        # Look for any key that contains a list of dictionaries
        for key, value in response.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
                
        return []
