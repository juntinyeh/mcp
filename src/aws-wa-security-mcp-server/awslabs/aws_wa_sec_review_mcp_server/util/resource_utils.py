# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""General utility functions for AWS resource operations."""

import boto3
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Set
from loguru import logger
from mcp.server.fastmcp import Context
from consts import DEFAULT_REGIONS


async def list_services_in_region(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """List all AWS services being used in a specific region.
    
    Args:
        region: AWS region to list services for
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with services information and counts
    """
    try:
        # Initialize the result dictionary
        result = {
            "region": region,
            "services": [],
            "service_counts": {},
            "total_resources": 0
        }
        
        # Use Resource Explorer to efficiently discover resources
        try:
            resource_explorer = session.client('resource-explorer-2', region_name=region)
            
            # Check if Resource Explorer is available in this region
            try:
                # Try to search with Resource Explorer
                response = resource_explorer.search(
                    QueryString="*",
                    MaxResults=1  # Just checking if it works
                )
            except Exception as e:
                if "Resource Explorer has not been set up" in str(e):
                    await ctx.warning(f"Resource Explorer not set up in {region}. Using alternative method.")
                    return await list_services_alternative(region, session, ctx)
                else:
                    raise e
                
            # Resource Explorer is available, use it to get all resources
            paginator = resource_explorer.get_paginator('search')
            page_iterator = paginator.paginate(
                QueryString="*",
                MaxResults=1000
            )
            
            # Track unique services
            services_set = set()
            service_resource_counts = {}
            
            # Process each page of results
            for page in page_iterator:
                for resource in page.get('Resources', []):
                    # Extract service from ARN
                    arn = resource.get('Arn', '')
                    if arn:
                        arn_parts = arn.split(':')
                        if len(arn_parts) >= 3:
                            service = arn_parts[2]
                            services_set.add(service)
                            
                            # Update count for this service
                            if service in service_resource_counts:
                                service_resource_counts[service] += 1
                            else:
                                service_resource_counts[service] = 1
            
            # Update result with discovered services
            result["services"] = sorted(list(services_set))
            result["service_counts"] = service_resource_counts
            result["total_resources"] = sum(service_resource_counts.values())
            
        except Exception as e:
            await ctx.warning(f"Error using Resource Explorer in {region}: {e}")
            # Fall back to alternative method
            return await list_services_alternative(region, session, ctx)
            
        return result
        
    except Exception as e:
        await ctx.error(f"Error listing services in region {region}: {e}")
        return {
            "region": region,
            "services": [],
            "error": str(e)
        }


async def list_services_alternative(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Alternative method to list services when Resource Explorer is not available.
    
    This method checks for the availability of commonly used services in the region.
    
    Args:
        region: AWS region to list services for
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with services information and counts
    """
    result = {
        "region": region,
        "services": [],
        "service_counts": {},
        "total_resources": 0
    }
    
    # List of common services to check
    common_services = [
        's3', 'ec2', 'rds', 'lambda', 'dynamodb', 'iam', 
        'cloudfront', 'kms', 'sns', 'sqs', 'ecs', 'eks',
        'elasticache', 'elb', 'apigateway', 'cloudwatch'
    ]
    
    services_with_resources = []
    service_resource_counts = {}
    total_resources = 0
    
    # Check each service for availability
    for service in common_services:
        try:
            # Skip global services if not in primary region
            if service in ['iam', 'cloudfront'] and region != 'us-east-1':
                continue
                
            # Try to create a client for the service to check if it's available
            client = session.client(service, region_name=region)
            
            # If we get here, the service is available
            services_with_resources.append(service)
            service_resource_counts[service] = 1  # Just mark as available
            total_resources += 1
            
        except Exception as e:
            await ctx.warning(f"Service {service} not available in region {region}: {e}")
    
    # Update result
    result["services"] = sorted(services_with_resources)
    result["service_counts"] = service_resource_counts
    result["total_resources"] = total_resources
    
    return result
