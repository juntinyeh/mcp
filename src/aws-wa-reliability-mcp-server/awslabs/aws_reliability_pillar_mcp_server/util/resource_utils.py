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
from ..consts import DEFAULT_REGIONS


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
                        
                        # Check for versioning (important for reliability)
                        try:
                            versioning = client.get_bucket_versioning(Bucket=bucket['Name'])
                            bucket_details['versioning'] = versioning.get('Status', 'Disabled')
                        except Exception as e:
                            await ctx.warning(f"Error getting versioning for bucket {bucket['Name']}: {e}")
                            bucket_details['versioning'] = 'Unknown'
                        
                        # Check for replication (important for reliability)
                        try:
                            replication = client.get_bucket_replication(Bucket=bucket['Name'])
                            bucket_details['replication'] = True
                            bucket_details['replication_rules'] = replication.get('ReplicationConfiguration', {}).get('Rules', [])
                        except Exception as e:
                            # Most likely the bucket doesn't have replication configured
                            bucket_details['replication'] = False
                            bucket_details['replication_rules'] = []
                        
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
                            'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'N/A'),
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
                    'backup_retention_period': db.get('BackupRetentionPeriod', 0),
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
                        'backup_retention_period': cluster.get('BackupRetentionPeriod', 0),
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
                    
                    # Check for point-in-time recovery (important for reliability)
                    try:
                        pitr = client.describe_continuous_backups(TableName=table_name)
                        pitr_status = pitr.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus', 'DISABLED')
                    except Exception as e:
                        await ctx.warning(f"Error getting PITR status for table {table_name}: {e}")
                        pitr_status = 'UNKNOWN'
                    
                    resources['tables'].append({
                        'name': table_details['TableName'],
                        'status': table_details['TableStatus'],
                        'item_count': table_details['ItemCount'],
                        'size_bytes': table_details['TableSizeBytes'],
                        'provisioned_throughput': {
                            'read_capacity_units': table_details['ProvisionedThroughput']['ReadCapacityUnits'],
                            'write_capacity_units': table_details['ProvisionedThroughput']['WriteCapacityUnits'],
                        },
                        'point_in_time_recovery': pitr_status
                    })
                except Exception as e:
                    await ctx.warning(f"Error describing DynamoDB table {table_name}: {e}")
        
        elif service == 'route53':
            # Only run in a single region since Route 53 is global
            if region == 'us-east-1':
                # Route 53 health checks
                response = client.list_health_checks()
                resources['health_checks'] = []
                for health_check in response['HealthChecks']:
                    health_check_details = {
                        'id': health_check['Id'],
                        'caller_reference': health_check['CallerReference'],
                        'health_check_config': health_check['HealthCheckConfig'],
                        'health_check_version': health_check['HealthCheckVersion']
                    }
                    resources['health_checks'].append(health_check_details)
                
                # Route 53 hosted zones
                response = client.list_hosted_zones()
                resources['hosted_zones'] = []
                for hosted_zone in response['HostedZones']:
                    hosted_zone_details = {
                        'id': hosted_zone['Id'],
                        'name': hosted_zone['Name'],
                        'record_set_count': hosted_zone['ResourceRecordSetCount'],
                        'private_zone': hosted_zone['Config']['PrivateZone']
                    }
                    resources['hosted_zones'].append(hosted_zone_details)
        
        elif service == 'cloudwatch':
            # CloudWatch alarms
            response = client.describe_alarms()
            resources['alarms'] = []
            
            # Process metric alarms
            for alarm in response.get('MetricAlarms', []):
                alarm_details = {
                    'name': alarm['AlarmName'],
                    'description': alarm.get('AlarmDescription', ''),
                    'state': alarm['StateValue'],
                    'metric_name': alarm['MetricName'],
                    'namespace': alarm['Namespace'],
                    'statistic': alarm['Statistic'],
                    'dimensions': alarm.get('Dimensions', []),
                    'period': alarm['Period'],
                    'threshold': alarm['Threshold'],
                    'comparison_operator': alarm['ComparisonOperator'],
                    'actions_enabled': alarm['ActionsEnabled'],
                    'alarm_actions': alarm.get('AlarmActions', []),
                    'ok_actions': alarm.get('OKActions', []),
                    'insufficient_data_actions': alarm.get('InsufficientDataActions', [])
                }
                resources['alarms'].append(alarm_details)
            
            # Process composite alarms
            for alarm in response.get('CompositeAlarms', []):
                alarm_details = {
                    'name': alarm['AlarmName'],
                    'description': alarm.get('AlarmDescription', ''),
                    'state': alarm['StateValue'],
                    'rule': alarm['AlarmRule'],
                    'actions_enabled': alarm['ActionsEnabled'],
                    'alarm_actions': alarm.get('AlarmActions', []),
                    'ok_actions': alarm.get('OKActions', []),
                    'insufficient_data_actions': alarm.get('InsufficientDataActions', [])
                }
                resources['alarms'].append(alarm_details)
        
        elif service == 'autoscaling':
            # Auto Scaling groups
            response = client.describe_auto_scaling_groups()
            resources['auto_scaling_groups'] = []
            for asg in response['AutoScalingGroups']:
                asg_details = {
                    'name': asg.get('AutoScalingGroupName'),
                    'launch_configuration_name': asg.get('LaunchConfigurationName'),
                    'launch_template': asg.get('LaunchTemplate'),
                    'min_size': asg['MinSize'],
                    'max_size': asg['MaxSize'],
                    'desired_capacity': asg['DesiredCapacity'],
                    'availability_zones': asg['AvailabilityZones'],
                    'load_balancer_names': asg.get('LoadBalancerNames', []),
                    'target_group_arns': asg.get('TargetGroupARNs', []),
                    'health_check_type': asg['HealthCheckType'],
                    'health_check_grace_period': asg['HealthCheckGracePeriod'],
                    'instances': [
                        {
                            'id': instance['InstanceId'],
                            'health_status': instance['HealthStatus'],
                            'lifecycle_state': instance['LifecycleState'],
                            'availability_zone': instance['AvailabilityZone']
                        }
                        for instance in asg.get('Instances', [])
                    ]
                }
                resources['auto_scaling_groups'].append(asg_details)
        
        elif service == 'elb':
            # Classic Load Balancers
            response = client.describe_load_balancers()
            resources['load_balancers'] = []
            for lb in response['LoadBalancerDescriptions']:
                lb_details = {
                    'name': lb['LoadBalancerName'],
                    'type': 'classic',
                    'dns_name': lb['DNSName'],
                    'availability_zones': lb['AvailabilityZones'],
                    'vpc_id': lb.get('VPCId'),
                    'instances': [instance['InstanceId'] for instance in lb.get('Instances', [])],
                    'health_check': lb.get('HealthCheck')
                }
                resources['load_balancers'].append(lb_details)
        
        elif service == 'elbv2':
            # Application and Network Load Balancers
            response = client.describe_load_balancers()
            if 'load_balancers' not in resources:
                resources['load_balancers'] = []
            
            for lb in response['LoadBalancers']:
                lb_details = {
                    'name': lb['LoadBalancerName'],
                    'type': lb['Type'],
                    'dns_name': lb['DNSName'],
                    'availability_zones': [
                        {
                            'zone_name': az['ZoneName'],
                            'subnet_id': az['SubnetId']
                        }
                        for az in lb.get('AvailabilityZones', [])
                    ],
                    'vpc_id': lb.get('VpcId'),
                    'state': lb.get('State', {}).get('Code')
                }
                
                # Get target groups
                try:
                    target_groups_response = client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                    lb_details['target_groups'] = [
                        {
                            'name': tg['TargetGroupName'],
                            'arn': tg['TargetGroupArn'],
                            'protocol': tg['Protocol'],
                            'port': tg['Port'],
                            'target_type': tg['TargetType'],
                            'vpc_id': tg['VpcId']
                        }
                        for tg in target_groups_response['TargetGroups']
                    ]
                except Exception as e:
                    await ctx.warning(f"Error getting target groups for load balancer {lb['LoadBalancerName']}: {e}")
                    lb_details['target_groups'] = []
                
                resources['load_balancers'].append(lb_details)
        
        elif service == 'backup':
            # AWS Backup vaults
            response = client.list_backup_vaults()
            resources['backup_vaults'] = []
            for vault in response['BackupVaultList']:
                vault_details = {
                    'name': vault['BackupVaultName'],
                    'arn': vault['BackupVaultArn'],
                    'creation_date': str(vault['CreationDate']),
                    'encryption_key_arn': vault.get('EncryptionKeyArn')
                }
                resources['backup_vaults'].append(vault_details)
            
            # AWS Backup plans
            try:
                response = client.list_backup_plans()
                resources['backup_plans'] = []
                for plan in response['BackupPlansList']:
                    plan_details = {
                        'name': plan['BackupPlanName'],
                        'arn': plan['BackupPlanArn'],
                        'version_id': plan['VersionId'],
                        'creation_date': str(plan['CreationDate']),
                        'last_execution_date': str(plan.get('LastExecutionDate', ''))
                    }
                    resources['backup_plans'].append(plan_details)
            except Exception as e:
                await ctx.warning(f"Error listing backup plans: {e}")
        
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
        'resources_by_service': {},
        'reliability_metrics': {
            'multi_az_resources': 0,
            'single_az_resources': 0,
            'resources_with_backups': 0,
            'resources_without_backups': 0,
            'monitored_resources': 0,
            'unmonitored_resources': 0
        }
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
                
                # Update reliability metrics
                if resource_type == 'db_instances':
                    # Count RDS instances with Multi-AZ
                    multi_az_count = len([db for db in items if db.get('multi_az', False)])
                    summary['reliability_metrics']['multi_az_resources'] += multi_az_count
                    summary['reliability_metrics']['single_az_resources'] += (item_count - multi_az_count)
                    
                    # Count RDS instances with backups
                    with_backups = len([db for db in items if db.get('backup_retention_period', 0) > 0])
                    summary['reliability_metrics']['resources_with_backups'] += with_backups
                    summary['reliability_metrics']['resources_without_backups'] += (item_count - with_backups)
                
                elif resource_type == 'instances':
                    # Count EC2 instances by AZ
                    instances_by_az = {}
                    for instance in items:
                        az = instance.get('availability_zone')
                        if az:
                            if az in instances_by_az:
                                instances_by_az[az].append(instance)
                            else:
                                instances_by_az[az] = [instance]
                    
                    if len(instances_by_az) > 1:
                        summary['reliability_metrics']['multi_az_resources'] += item_count
                    else:
                        summary['reliability_metrics']['single_az_resources'] += item_count
                
                elif resource_type == 'tables':
                    # Count DynamoDB tables with point-in-time recovery
                    with_pitr = len([table for table in items if table.get('point_in_time_recovery') == 'ENABLED'])
                    summary['reliability_metrics']['resources_with_backups'] += with_pitr
                    summary['reliability_metrics']['resources_without_backups'] += (item_count - with_pitr)
                
                elif resource_type == 'buckets':
                    # Count S3 buckets with versioning
                    with_versioning = len([bucket for bucket in items if bucket.get('versioning') == 'Enabled'])
                    summary['reliability_metrics']['resources_with_backups'] += with_versioning
                    summary['reliability_metrics']['resources_without_backups'] += (item_count - with_versioning)
                    
                    # Count S3 buckets with replication
                    with_replication = len([bucket for bucket in items if bucket.get('replication', False)])
                    summary['reliability_metrics']['multi_az_resources'] += with_replication
                    summary['reliability_metrics']['single_az_resources'] += (item_count - with_replication)
            
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
    """Get compliance status for an AWS resource against reliability best practices.
    
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
        compliance_status = 'UNKNOWN'
        compliance_details = {}
        
        # Check compliance based on resource type
        if resource_type == 'ec2-instance':
            # Create EC2 client
            ec2_client = session.client('ec2', region_name=region)
            
            # Get instance details
            response = ec2_client.describe_instances(InstanceIds=[resource_id])
            if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                return {
                    'resource_id': resource_id,
                    'type': resource_type,
                    'compliance_status': 'UNKNOWN',
                    'message': 'Instance not found'
                }
            
            instance = response['Reservations'][0]['Instances'][0]
            
            # Check for compliance with reliability best practices
            compliance_details = {
                'multi_az': False,
                'has_backup': False,
                'monitored': False,
                'auto_recovery': False
            }
            
            # Check if instance is part of an Auto Scaling group
            asg_client = session.client('autoscaling', region_name=region)
            asg_response = asg_client.describe_auto_scaling_instances(InstanceIds=[resource_id])
            in_asg = len(asg_response['AutoScalingInstances']) > 0
            compliance_details['in_auto_scaling_group'] = in_asg
            
            # Check if instance has detailed monitoring enabled
            compliance_details['detailed_monitoring'] = instance.get('Monitoring', {}).get('State') == 'enabled'
            
            # Check if instance has auto recovery enabled
            try:
                alarm_client = session.client('cloudwatch', region_name=region)
                alarms = alarm_client.describe_alarms_for_metric(
                    MetricName='StatusCheckFailed_System',
                    Namespace='AWS/EC2',
                    Dimensions=[
                        {
                            'Name': 'InstanceId',
                            'Value': resource_id
                        }
                    ]
                )
                compliance_details['auto_recovery'] = len(alarms['MetricAlarms']) > 0
            except Exception as e:
                await ctx.warning(f"Error checking auto recovery for instance {resource_id}: {e}")
            
            # Determine overall compliance status
            if in_asg and compliance_details['detailed_monitoring'] and compliance_details['auto_recovery']:
                compliance_status = 'COMPLIANT'
            else:
                compliance_status = 'NON_COMPLIANT'
            
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'compliance_status': compliance_status,
                'compliance_details': compliance_details,
                'recommendations': [
                    'Use Auto Scaling groups for automatic recovery and scaling',
                    'Enable detailed monitoring for better visibility',
                    'Configure CloudWatch alarms for auto recovery'
                ] if compliance_status == 'NON_COMPLIANT' else []
            }
        
        elif resource_type == 's3-bucket':
            # Create S3 client
            s3_client = session.client('s3', region_name=region)
            
            # Check for versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=resource_id)
                versioning_enabled = versioning.get('Status') == 'Enabled'
            except Exception as e:
                await ctx.warning(f"Error checking versioning for bucket {resource_id}: {e}")
                versioning_enabled = False
            
            # Check for replication
            try:
                replication = s3_client.get_bucket_replication(Bucket=resource_id)
                replication_enabled = 'ReplicationConfiguration' in replication
            except Exception as e:
                # Most likely the bucket doesn't have replication configured
                replication_enabled = False
            
            # Check for encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=resource_id)
                encryption_enabled = 'ServerSideEncryptionConfiguration' in encryption
            except Exception as e:
                encryption_enabled = False
            
            # Determine overall compliance status
            compliance_details = {
                'versioning': versioning_enabled,
                'replication': replication_enabled,
                'encryption': encryption_enabled
            }
            
            if versioning_enabled and replication_enabled and encryption_enabled:
                compliance_status = 'COMPLIANT'
            else:
                compliance_status = 'NON_COMPLIANT'
            
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'compliance_status': compliance_status,
                'compliance_details': compliance_details,
                'recommendations': [
                    'Enable versioning to protect against accidental deletion',
                    'Configure cross-region replication for disaster recovery',
                    'Enable server-side encryption for data protection'
                ] if compliance_status == 'NON_COMPLIANT' else []
            }
        
        elif resource_type == 'rds-db-instance':
            # Create RDS client
            rds_client = session.client('rds', region_name=region)
            
            # Get DB instance details
            response = rds_client.describe_db_instances(DBInstanceIdentifier=resource_id)
            if not response['DBInstances']:
                return {
                    'resource_id': resource_id,
                    'type': resource_type,
                    'compliance_status': 'UNKNOWN',
                    'message': 'DB instance not found'
                }
            
            db_instance = response['DBInstances'][0]
            
            # Check for compliance with reliability best practices
            compliance_details = {
                'multi_az': db_instance.get('MultiAZ', False),
                'backup_retention_period': db_instance.get('BackupRetentionPeriod', 0),
                'storage_encrypted': db_instance.get('StorageEncrypted', False),
                'deletion_protection': db_instance.get('DeletionProtection', False)
            }
            
            # Determine overall compliance status
            if (compliance_details['multi_az'] and 
                compliance_details['backup_retention_period'] >= 7 and 
                compliance_details['storage_encrypted'] and 
                compliance_details['deletion_protection']):
                compliance_status = 'COMPLIANT'
            else:
                compliance_status = 'NON_COMPLIANT'
            
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'compliance_status': compliance_status,
                'compliance_details': compliance_details,
                'recommendations': [
                    'Enable Multi-AZ deployment for high availability',
                    'Set backup retention period to at least 7 days',
                    'Enable storage encryption for data protection',
                    'Enable deletion protection to prevent accidental deletion'
                ] if compliance_status == 'NON_COMPLIANT' else []
            }
        
        elif resource_type == 'dynamodb-table':
            # Create DynamoDB client
            dynamodb_client = session.client('dynamodb', region_name=region)
            
            # Get table details
            response = dynamodb_client.describe_table(TableName=resource_id)
            if not response.get('Table'):
                return {
                    'resource_id': resource_id,
                    'type': resource_type,
                    'compliance_status': 'UNKNOWN',
                    'message': 'Table not found'
                }
            
            table = response['Table']
            
            # Check for point-in-time recovery
            try:
                pitr = dynamodb_client.describe_continuous_backups(TableName=resource_id)
                pitr_enabled = pitr.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus') == 'ENABLED'
            except Exception as e:
                await ctx.warning(f"Error checking PITR for table {resource_id}: {e}")
                pitr_enabled = False
            
            # Check for global tables (multi-region)
            try:
                global_tables = dynamodb_client.describe_global_table(GlobalTableName=resource_id)
                global_table_enabled = len(global_tables.get('GlobalTableDescription', {}).get('ReplicationGroup', [])) > 1
            except Exception as e:
                global_table_enabled = False
            
            # Determine overall compliance status
            compliance_details = {
                'point_in_time_recovery': pitr_enabled,
                'global_table': global_table_enabled,
                'provisioned_throughput': table.get('ProvisionedThroughput', {})
            }
            
            if pitr_enabled and global_table_enabled:
                compliance_status = 'COMPLIANT'
            else:
                compliance_status = 'NON_COMPLIANT'
            
            return {
                'resource_id': resource_id,
                'type': resource_type,
                'compliance_status': compliance_status,
                'compliance_details': compliance_details,
                'recommendations': [
                    'Enable point-in-time recovery for data protection',
                    'Configure as a global table for multi-region availability'
                ] if compliance_status == 'NON_COMPLIANT' else []
            }
        
        # Default case for unsupported resource types
        return {
            'resource_id': resource_id,
            'type': resource_type,
            'compliance_status': 'UNKNOWN',
            'message': f'Compliance checking not implemented for resource type {resource_type}'
        }
    except Exception as e:
        await ctx.error(f"Error getting compliance status for {resource_type} {resource_id}: {e}")
        return {
            'resource_id': resource_id,
            'type': resource_type,
            'compliance_status': 'ERROR',
            'message': str(e)
        }
