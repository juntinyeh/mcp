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

"""General utility functions for AWS resource operations."""

import boto3
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Set
from loguru import logger
from mcp.server.fastmcp import Context
from consts import DEFAULT_REGIONS


async def list_aws_regions(session: boto3.Session) -> List[str]:
    """Get a list of all available AWS regions.
    
    Args:
        session: boto3 Session for AWS API calls
        
    Returns:
        List of region names
    """
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except Exception as e:
        logger.error(f"Error listing AWS regions: {e}")
        # Return some common regions as fallback
        return DEFAULT_REGIONS


async def list_resources_by_service(
    region: str, 
    service: str, 
    session: boto3.Session, 
    ctx: Context,
    resource_type: Optional[str] = None
) -> Dict[str, List[Dict]]:
    """List AWS resources for a specific service in a region.
    
    Args:
        region: AWS region to list resources for
        service: AWS service to list resources for (e.g., 's3', 'ec2')
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        resource_type: Optional specific resource type within the service
        
    Returns:
        Dictionary mapping resource types to lists of resources
    """
    try:
        resources = {}
        
        # Create a client for the requested service
        client = session.client(service, region_name=region)
        
        # Handle different services
        if service == 's3':
            # S3 buckets are global but have regional settings
            response = client.list_buckets()
            resources['buckets'] = []
            for bucket in response['Buckets']:
                # Try to get the bucket location
                try:
                    location = client.get_bucket_location(Bucket=bucket['Name'])
                    bucket_region = location.get('LocationConstraint')
                    # us-east-1 returns None for the location constraint
                    if bucket_region is None:
                        bucket_region = 'us-east-1'
                        
                    # Only include if in the specified region
                    if bucket_region == region:
                        # Add bucket details
                        bucket_details = {
                            'name': bucket['Name'],
                            'creation_date': str(bucket['CreationDate']),
                            'region': bucket_region
                        }
                        resources['buckets'].append(bucket_details)
                except Exception as e:
                    await ctx.warning(f"Error getting location for bucket {bucket['Name']}: {e}")
        
        elif service == 'ec2':
            # EC2 instances
            if not resource_type or resource_type == 'instances':
                response = client.describe_instances()
                resources['instances'] = []
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_details = {
                            'id': instance['InstanceId'],
                            'type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                            'public_ip': instance.get('PublicIpAddress', 'N/A'),
                            'vpc_id': instance.get('VpcId', 'N/A'),
                            'subnet_id': instance.get('SubnetId', 'N/A'),
                            'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        }
                        resources['instances'].append(instance_details)
            
            # Security groups
            if not resource_type or resource_type == 'security_groups':
                response = client.describe_security_groups()
                resources['security_groups'] = []
                for sg in response['SecurityGroups']:
                    sg_details = {
                        'id': sg['GroupId'],
                        'name': sg['GroupName'],
                        'description': sg['Description'],
                        'vpc_id': sg.get('VpcId', 'N/A'),
                        'ingress_rules': sg['IpPermissions'],
                        'egress_rules': sg['IpPermissionsEgress'],
                        'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                    }
                    resources['security_groups'].append(sg_details)
            
            # VPCs
            if not resource_type or resource_type == 'vpcs':
                response = client.describe_vpcs()
                resources['vpcs'] = []
                for vpc in response['Vpcs']:
                    vpc_details = {
                        'id': vpc['VpcId'],
                        'cidr_block': vpc['CidrBlock'],
                        'state': vpc['State'],
                        'is_default': vpc['IsDefault'],
                        'tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                    }
                    resources['vpcs'].append(vpc_details)
                    
            # Subnets
            if not resource_type or resource_type == 'subnets':
                response = client.describe_subnets()
                resources['subnets'] = []
                for subnet in response['Subnets']:
                    subnet_details = {
                        'id': subnet['SubnetId'],
                        'vpc_id': subnet['VpcId'],
                        'cidr_block': subnet['CidrBlock'],
                        'availability_zone': subnet['AvailabilityZone'],
                        'state': subnet['State'],
                        'tags': {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                    }
                    resources['subnets'].append(subnet_details)
        
        elif service == 'rds':
            # RDS instances
            response = client.describe_db_instances()
            resources['db_instances'] = []
            for db in response['DBInstances']:
                db_details = {
                    'id': db['DBInstanceIdentifier'],
                    'engine': db['Engine'],
                    'status': db['DBInstanceStatus'],
                    'storage': db['AllocatedStorage'],
                    'endpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
                    'vpc_id': db.get('DBSubnetGroup', {}).get('VpcId', 'N/A'),
                    'multi_az': db['MultiAZ'],
                    'tags': {tag['Key']: tag['Value'] for tag in client.list_tags_for_resource(ResourceName=db['DBInstanceArn'])['TagList']}
                }
                resources['db_instances'].append(db_details)
                
            # RDS clusters
            try:
                response = client.describe_db_clusters()
                resources['db_clusters'] = []
                for cluster in response['DBClusters']:
                    cluster_details = {
                        'id': cluster['DBClusterIdentifier'],
                        'engine': cluster['Engine'],
                        'status': cluster['Status'],
                        'endpoint': cluster.get('Endpoint', 'N/A'),
                        'reader_endpoint': cluster.get('ReaderEndpoint', 'N/A'),
                        'multi_az': cluster['MultiAZ'],
                        'tags': {tag['Key']: tag['Value'] for tag in client.list_tags_for_resource(ResourceName=cluster['DBClusterArn'])['TagList']}
                    }
                    resources['db_clusters'].append(cluster_details)
            except Exception as e:
                await ctx.warning(f"Error listing RDS clusters: {e}")
        
        elif service == 'lambda':
            # Lambda functions
            response = client.list_functions()
            resources['functions'] = []
            for fn in response['Functions']:
                function_details = {
                    'name': fn['FunctionName'],
                    'arn': fn['FunctionArn'],
                    'runtime': fn['Runtime'],
                    'handler': fn['Handler'],
                    'role': fn['Role'],
                    'memory': fn['MemorySize'],
                    'timeout': fn['Timeout'],
                    'last_modified': fn['LastModified']
                }
                # Get tags
                try:
                    tags_response = client.list_tags(Resource=fn['FunctionArn'])
                    function_details['tags'] = tags_response.get('Tags', {})
                except Exception as e:
                    await ctx.warning(f"Error getting tags for Lambda function {fn['FunctionName']}: {e}")
                
                resources['functions'].append(function_details)
        
        elif service == 'dynamodb':
            # DynamoDB tables
            response = client.list_tables()
            table_names = response['TableNames']
            resources['tables'] = []
            
            for table_name in table_names:
                try:
                    table_details = client.describe_table(TableName=table_name)['Table']
                    resources['tables'].append({
                        'name': table_details['TableName'],
                        'status': table_details['TableStatus'],
                        'item_count': table_details['ItemCount'],
                        'size_bytes': table_details['TableSizeBytes'],
                        'provisioned_throughput': {
                            'read_capacity_units': table_details['ProvisionedThroughput']['ReadCapacityUnits'],
                            'write_capacity_units': table_details['ProvisionedThroughput']['WriteCapacityUnits'],
                        }
                    })
                except Exception as e:
                    await ctx.warning(f"Error describing DynamoDB table {table_name}: {e}")
        
        elif service == 'iam':
            # Only run in a single region since IAM is global
            if region == 'us-east-1':
                # IAM users
                response = client.list_users()
                resources['users'] = []
                for user in response['Users']:
                    user_details = {
                        'name': user['UserName'],
                        'id': user['UserId'],
                        'arn': user['Arn'],
                        'path': user['Path'],
                        'create_date': str(user['CreateDate'])
                    }
                    resources['users'].append(user_details)
                
                # IAM roles
                response = client.list_roles()
                resources['roles'] = []
                for role in response['Roles']:
                    role_details = {
                        'name': role['RoleName'],
                        'id': role['RoleId'],
                        'arn': role['Arn'],
                        'path': role['Path'],
                        'create_date': str(role['CreateDate'])
                    }
                    resources['roles'].append(role_details)
        
        elif service == 'cloudfront':
            # Only run in a single region since CloudFront is global
            if region == 'us-east-1':
                # CloudFront distributions
                response = client.list_distributions()
                resources['distributions'] = []
                
                if 'Items' in response.get('DistributionList', {}):
                    for dist in response['DistributionList']['Items']:
                        dist_details = {
                            'id': dist['Id'],
                            'domain_name': dist['DomainName'],
                            'enabled': dist['Enabled'],
                            'origins': [origin['DomainName'] for origin in dist['Origins']['Items']],
                            'status': dist['Status'],
                            'price_class': dist['PriceClass']
                        }
                        resources['distributions'].append(dist_details)
        
        elif service == 'kms':
            # KMS keys
            response = client.list_keys()
            resources['keys'] = []
            
            for key in response['Keys']:
                try:
                    key_details = client.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                    
                    # Only include keys in the current region
                    if key_details['KeyManager'] != 'AWS':  # Skip AWS managed keys
                        resources['keys'].append({
                            'id': key_details['KeyId'],
                            'arn': key_details['Arn'],
                            'state': key_details['KeyState'],
                            'description': key_details.get('Description', ''),
                            'enabled': key_details['Enabled'],
                            'creation_date': str(key_details['CreationDate'])
                        })
                except Exception as e:
                    await ctx.warning(f"Error describing KMS key {key['KeyId']}: {e}")
        
        # Add more services as needed...
        
        return resources
    except Exception as e:
        await ctx.error(f"Error listing resources for service {service} in region {region}: {e}")
        return {}


async def list_all_resources(
    regions: List[str], 
    services: List[str], 
    session: boto3.Session, 
    ctx: Context,
    parallel: bool = True
) -> Dict[str, Dict[str, Any]]:
    """List all AWS resources for specified services across multiple regions.
    
    Args:
        regions: List of AWS regions to list resources for
        services: List of AWS services to list resources for
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        parallel: Whether to scan regions in parallel
        
    Returns:
        Dictionary mapping regions to service resources
    """
    all_resources = {}
    
    if parallel:
        # Use concurrent.futures to scan regions in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            region_futures = {}
            
            for region in regions:
                all_resources[region] = {}
                
                for service in services:
                    # Submit the task to the executor
                    future = executor.submit(
                        list_resources_by_service, 
                        region, 
                        service, 
                        session, 
                        ctx
                    )
                    region_futures[(region, service)] = future
            
            # Process completed futures
            for (region, service), future in region_futures.items():
                try:
                    service_resources = future.result()
                    if service_resources:
                        all_resources[region][service] = service_resources
                except Exception as e:
                    await ctx.warning(f"Error scanning {service} in {region}: {e}")
    else:
        # Scan regions sequentially
        for region in regions:
            await ctx.progress(message=f"Scanning region {region}...")
            all_resources[region] = {}
            
            for service in services:
                await ctx.progress(message=f"Scanning {service} in {region}...")
                service_resources = await list_resources_by_service(region, service, session, ctx)
                if service_resources:
                    all_resources[region][service] = service_resources
    
    return all_resources


async def resource_inventory_summary(resources: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a summary of the AWS resource inventory.
    
    Args:
        resources: Output from list_all_resources
        
    Returns:
        Summary dictionary with resource counts and other metrics
    """
    summary = {
        'total_regions': len(resources),
        'total_services': 0,
        'resource_counts': {},
        'resources_by_region': {},
        'resources_by_service': {}
    }
    
    service_set = set()
    
    for region, services in resources.items():
        summary['resources_by_region'][region] = {}
        region_resource_count = 0
        
        for service, resource_types in services.items():
            service_set.add(service)
            if service not in summary['resources_by_service']:
                summary['resources_by_service'][service] = 0
                
            service_resource_count = 0
            
            for resource_type, items in resource_types.items():
                item_count = len(items)
                
                # Update resource type count
                if resource_type not in summary['resource_counts']:
                    summary['resource_counts'][resource_type] = item_count
                else:
                    summary['resource_counts'][resource_type] += item_count
                
                # Update service count for this region
                if service not in summary['resources_by_region'][region]:
                    summary['resources_by_region'][region][service] = item_count
                else:
                    summary['resources_by_region'][region][service] += item_count
                
                # Update total service count
                summary['resources_by_service'][service] += item_count
                
                # Update resource count for this region and service
                service_resource_count += item_count
            
            region_resource_count += service_resource_count
        
        # Calculate total resources per region
        summary['resources_by_region'][region]['total'] = region_resource_count
    
    summary['total_services'] = len(service_set)
    summary['total_resources'] = sum(summary['resources_by_service'].values())
    
    return summary


async def get_tagged_resources(
    regions: List[str], 
    tag_key: Optional[str] = None,
    tag_value: Optional[str] = None,
    session: boto3.Session = None, 
    ctx: Context = None
) -> Dict[str, List[Dict]]:
    """Find AWS resources with specific tags across regions.
    
    Args:
        regions: List of AWS regions to search in
        tag_key: Optional tag key to filter by
        tag_value: Optional tag value to filter by (if tag_key is provided)
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary mapping regions to lists of matching resources
    """
    results = {}
    
    for region in regions:
        if ctx:
            await ctx.progress(message=f"Searching for tagged resources in {region}...")
        
        try:
            client = session.client('resourcegroupstaggingapi', region_name=region)
            
            filters = {}
            if tag_key:
                if tag_value:
                    filters['TagFilters'] = [{'Key': tag_key, 'Values': [tag_value]}]
                else:
                    filters['TagFilters'] = [{'Key': tag_key}]
            
            response = client.get_resources(**filters)
            
            if response['ResourceTagMappingList']:
                results[region] = []
                
                for resource in response['ResourceTagMappingList']:
                    resource_arn = resource['ResourceARN']
                    tags = {tag['Key']: tag['Value'] for tag in resource['Tags']}
                    
                    # Parse resource type from ARN
                    arn_parts = resource_arn.split(':')
                    if len(arn_parts) >= 6:
                        service = arn_parts[2]
                        resource_type = arn_parts[5].split('/')[0] if '/' in arn_parts[5] else arn_parts[5]
                    else:
                        service = "unknown"
                        resource_type = "unknown"
                    
                    results[region].append({
                        'arn': resource_arn,
                        'service': service,
                        'resource_type': resource_type,
                        'tags': tags
                    })
        
        except Exception as e:
            if ctx:
                await ctx.warning(f"Error getting tagged resources in {region}: {e}")
    
    return results


async def get_resource_compliance_status(
    region: str,
    resource_id: str,
    resource_type: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Get compliance status for an AWS resource.
    
    Args:
        region: AWS region where the resource is located
        resource_id: The resource identifier
        resource_type: The AWS resource type
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with compliance information
    """
    try:
        # AWS Config can provide compliance information
        config_client = session.client('config', region_name=region)
        
        # Format resource type for Config
        resource_type_map = {
            'ec2-instance': 'AWS::EC2::Instance',
            's3-bucket': 'AWS::S3::Bucket',
            'iam-role': 'AWS::IAM::Role',
            'rds-db-instance': 'AWS::RDS::DBInstance',
            'dynamodb-table': 'AWS::DynamoDB::Table',
            'lambda-function': 'AWS::Lambda::Function',
            'security-group': 'AWS::EC2::SecurityGroup',
            'vpc': 'AWS::EC2::VPC',
            'subnet': 'AWS::EC2::Subnet',
            'kms-key': 'AWS::KMS::Key',
            # Add more mappings as needed
        }
        
        config_resource_type = resource_type_map.get(resource_type)
        if not config_resource_type:
            config_resource_type = resource_type
        
        # Get compliance details
        response = config_client.get_resource_config_history(
            resourceType=config_resource_type,
            resourceId=resource_id
        )
        
        if not response['configurationItems']:
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'compliance_status': 'UNKNOWN',
                'message': 'No configuration history found in AWS Config'
            }
        
        # Get latest configuration
        latest_config = response['configurationItems'][0]
        
        # Get compliance
        try:
            compliance_response = config_client.get_compliance_details_by_resource(
                ResourceType=config_resource_type,
                ResourceId=resource_id
            )
            
            compliance_by_rule = {}
            
            for result in compliance_response.get('EvaluationResults', []):
                rule_name = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ConfigRuleName']
                compliance = result['ComplianceType']
                
                compliance_by_rule[rule_name] = {
                    'status': compliance,
                    'last_evaluation': str(result.get('ConfigRuleInvokedTime', '')),
                }
            
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'arn': latest_config.get('arn', ''),
                'compliance_status': 'COMPLIANT' if all(r['status'] == 'COMPLIANT' for r in compliance_by_rule.values()) else 'NON_COMPLIANT',
                'configuration': latest_config.get('configuration', {}),
                'compliance_by_rule': compliance_by_rule,
                'last_updated': str(latest_config.get('configurationItemCaptureTime', ''))
            }
            
        except Exception as e:
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'arn': latest_config.get('arn', ''),
                'compliance_status': 'UNKNOWN',
                'message': f'Error getting compliance: {str(e)}',
                'configuration': latest_config.get('configuration', {}),
                'last_updated': str(latest_config.get('configurationItemCaptureTime', ''))
            }
            
    except Exception as e:
        await ctx.error(f"Error getting compliance status for {resource_type} {resource_id}: {e}")
        return {
            'resource_id': resource_id,
            'type': resource_type,
            'compliance_status': 'ERROR',
            'message': str(e)
        }
