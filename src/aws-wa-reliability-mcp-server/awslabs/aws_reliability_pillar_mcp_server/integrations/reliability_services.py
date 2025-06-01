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

"""Utility functions for checking AWS reliability services and retrieving findings."""

from typing import Dict, List, Any, Optional, Union
import boto3
import json
import datetime
from loguru import logger
from mcp.server.fastmcp import Context


async def check_route53_health_checks(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if Amazon Route 53 health checks are configured.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about Route 53 health checks
    """
    try:
        # Route 53 is a global service, so region doesn't matter
        # But we'll only check in us-east-1 to avoid duplicate checks
        if region != 'us-east-1':
            return {
                'enabled': True,
                'message': 'Route 53 is a global service, checked in us-east-1 region only.'
            }
        
        # Create Route 53 client
        route53_client = session.client('route53')
        
        # List health checks
        response = route53_client.list_health_checks()
        health_checks = response.get('HealthChecks', [])
        
        if not health_checks:
            return {
                'enabled': False,
                'health_checks': [],
                'setup_instructions': """
                # Amazon Route 53 Health Checks Setup Instructions
                
                No Route 53 health checks were found. Health checks are essential for monitoring the health and performance of your resources.
                
                To create a health check:
                
                1. Open the Route 53 console: https://console.aws.amazon.com/route53/
                2. Choose Health checks
                3. Choose Create health check
                4. Configure the health check settings
                5. Choose Create
                
                Learn more: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-creating.html
                """,
                'message': 'No Amazon Route 53 health checks found.'
            }
        
        # Process health checks
        health_check_details = []
        for health_check in health_checks:
            health_check_details.append({
                'id': health_check.get('Id'),
                'caller_reference': health_check.get('CallerReference'),
                'health_check_config': health_check.get('HealthCheckConfig'),
                'health_check_version': health_check.get('HealthCheckVersion')
            })
        
        return {
            'enabled': True,
            'health_checks': health_check_details,
            'message': f'Found {len(health_checks)} Route 53 health checks.'
        }
    except Exception as e:
        await ctx.error(f'Error checking Route 53 health checks: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Route 53 health checks.'
        }


async def check_cloudwatch_alarms(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if Amazon CloudWatch alarms are configured.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about CloudWatch alarms
    """
    try:
        # Create CloudWatch client
        cloudwatch_client = session.client('cloudwatch', region_name=region)
        
        # List alarms
        response = cloudwatch_client.describe_alarms()
        metric_alarms = response.get('MetricAlarms', [])
        composite_alarms = response.get('CompositeAlarms', [])
        
        total_alarms = len(metric_alarms) + len(composite_alarms)
        
        if total_alarms == 0:
            return {
                'enabled': False,
                'alarms': [],
                'setup_instructions': """
                # Amazon CloudWatch Alarms Setup Instructions
                
                No CloudWatch alarms were found. Alarms are essential for monitoring the health and performance of your resources.
                
                To create an alarm:
                
                1. Open the CloudWatch console: https://console.aws.amazon.com/cloudwatch/
                2. Choose Alarms
                3. Choose Create alarm
                4. Choose Select metric and select a metric to monitor
                5. Configure the alarm conditions
                6. Configure actions (e.g., SNS notification)
                7. Add a name and description
                8. Choose Create alarm
                
                Learn more: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
                """,
                'message': 'No Amazon CloudWatch alarms found.'
            }
        
        # Process alarms
        alarm_details = []
        for alarm in metric_alarms:
            alarm_details.append({
                'name': alarm.get('AlarmName'),
                'description': alarm.get('AlarmDescription'),
                'state': alarm.get('StateValue'),
                'metric_name': alarm.get('MetricName'),
                'namespace': alarm.get('Namespace'),
                'statistic': alarm.get('Statistic'),
                'dimensions': alarm.get('Dimensions'),
                'period': alarm.get('Period'),
                'threshold': alarm.get('Threshold'),
                'comparison_operator': alarm.get('ComparisonOperator'),
                'actions_enabled': alarm.get('ActionsEnabled')
            })
        
        for alarm in composite_alarms:
            alarm_details.append({
                'name': alarm.get('AlarmName'),
                'description': alarm.get('AlarmDescription'),
                'state': alarm.get('StateValue'),
                'rule': alarm.get('AlarmRule'),
                'actions_enabled': alarm.get('ActionsEnabled')
            })
        
        return {
            'enabled': True,
            'alarms': alarm_details,
            'message': f'Found {total_alarms} CloudWatch alarms ({len(metric_alarms)} metric alarms, {len(composite_alarms)} composite alarms).'
        }
    except Exception as e:
        await ctx.error(f'Error checking CloudWatch alarms: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking CloudWatch alarms.'
        }


async def check_auto_scaling_groups(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if AWS Auto Scaling groups are configured.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about Auto Scaling groups
    """
    try:
        # Create Auto Scaling client
        autoscaling_client = session.client('autoscaling', region_name=region)
        
        # List Auto Scaling groups
        response = autoscaling_client.describe_auto_scaling_groups()
        auto_scaling_groups = response.get('AutoScalingGroups', [])
        
        if not auto_scaling_groups:
            return {
                'enabled': False,
                'auto_scaling_groups': [],
                'setup_instructions': """
                # AWS Auto Scaling Setup Instructions
                
                No Auto Scaling groups were found. Auto Scaling helps ensure that you have the correct number of Amazon EC2 instances available to handle the load for your application.
                
                To create an Auto Scaling group:
                
                1. Open the Amazon EC2 console: https://console.aws.amazon.com/ec2/
                2. Choose Auto Scaling Groups
                3. Choose Create Auto Scaling group
                4. Follow the wizard to configure your Auto Scaling group
                
                Learn more: https://docs.aws.amazon.com/autoscaling/ec2/userguide/GettingStartedTutorial.html
                """,
                'message': 'No AWS Auto Scaling groups found.'
            }
        
        # Process Auto Scaling groups
        asg_details = []
        for asg in auto_scaling_groups:
            asg_details.append({
                'name': asg.get('AutoScalingGroupName'),
                'launch_configuration_name': asg.get('LaunchConfigurationName'),
                'launch_template': asg.get('LaunchTemplate'),
                'min_size': asg.get('MinSize'),
                'max_size': asg.get('MaxSize'),
                'desired_capacity': asg.get('DesiredCapacity'),
                'availability_zones': asg.get('AvailabilityZones'),
                'load_balancer_names': asg.get('LoadBalancerNames'),
                'target_group_arns': asg.get('TargetGroupARNs'),
                'health_check_type': asg.get('HealthCheckType'),
                'health_check_grace_period': asg.get('HealthCheckGracePeriod'),
                'instances': [
                    {
                        'id': instance.get('InstanceId'),
                        'health_status': instance.get('HealthStatus'),
                        'lifecycle_state': instance.get('LifecycleState'),
                        'availability_zone': instance.get('AvailabilityZone')
                    }
                    for instance in asg.get('Instances', [])
                ]
            })
        
        return {
            'enabled': True,
            'auto_scaling_groups': asg_details,
            'message': f'Found {len(auto_scaling_groups)} Auto Scaling groups.'
        }
    except Exception as e:
        await ctx.error(f'Error checking Auto Scaling groups: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Auto Scaling groups.'
        }


async def check_load_balancers(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if Elastic Load Balancers are configured.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about Elastic Load Balancers
    """
    try:
        # Create ELB clients
        elb_client = session.client('elb', region_name=region)
        elbv2_client = session.client('elbv2', region_name=region)
        
        # List Classic Load Balancers
        classic_response = elb_client.describe_load_balancers()
        classic_lbs = classic_response.get('LoadBalancerDescriptions', [])
        
        # List Application and Network Load Balancers
        elbv2_response = elbv2_client.describe_load_balancers()
        elbv2_lbs = elbv2_response.get('LoadBalancers', [])
        
        total_lbs = len(classic_lbs) + len(elbv2_lbs)
        
        if total_lbs == 0:
            return {
                'enabled': False,
                'load_balancers': [],
                'setup_instructions': """
                # Elastic Load Balancing Setup Instructions
                
                No load balancers were found. Elastic Load Balancing automatically distributes incoming application traffic across multiple targets, such as Amazon EC2 instances, containers, IP addresses, and Lambda functions.
                
                To create a load balancer:
                
                1. Open the Amazon EC2 console: https://console.aws.amazon.com/ec2/
                2. Choose Load Balancers
                3. Choose Create Load Balancer
                4. Choose the type of load balancer to create
                5. Follow the wizard to configure your load balancer
                
                Learn more: https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/load-balancer-getting-started.html
                """,
                'message': 'No Elastic Load Balancers found.'
            }
        
        # Process load balancers
        lb_details = []
        
        # Process Classic Load Balancers
        for lb in classic_lbs:
            lb_details.append({
                'name': lb.get('LoadBalancerName'),
                'type': 'classic',
                'dns_name': lb.get('DNSName'),
                'availability_zones': lb.get('AvailabilityZones'),
                'vpc_id': lb.get('VPCId'),
                'instances': [instance.get('InstanceId') for instance in lb.get('Instances', [])],
                'health_check': lb.get('HealthCheck')
            })
        
        # Process Application and Network Load Balancers
        for lb in elbv2_lbs:
            lb_details.append({
                'name': lb.get('LoadBalancerName'),
                'type': lb.get('Type'),
                'dns_name': lb.get('DNSName'),
                'availability_zones': [
                    {
                        'zone_name': az.get('ZoneName'),
                        'subnet_id': az.get('SubnetId')
                    }
                    for az in lb.get('AvailabilityZones', [])
                ],
                'vpc_id': lb.get('VpcId'),
                'state': lb.get('State', {}).get('Code')
            })
        
        return {
            'enabled': True,
            'load_balancers': lb_details,
            'message': f'Found {total_lbs} load balancers ({len(classic_lbs)} Classic, {len(elbv2_lbs)} Application/Network).'
        }
    except Exception as e:
        await ctx.error(f'Error checking load balancers: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking load balancers.'
        }


async def check_backup_vaults(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if AWS Backup vaults are configured.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about AWS Backup vaults
    """
    try:
        # Create Backup client
        backup_client = session.client('backup', region_name=region)
        
        # List backup vaults
        response = backup_client.list_backup_vaults()
        backup_vaults = response.get('BackupVaultList', [])
        
        if not backup_vaults:
            return {
                'enabled': False,
                'backup_vaults': [],
                'setup_instructions': """
                # AWS Backup Setup Instructions
                
                No AWS Backup vaults were found. AWS Backup is a fully managed backup service that makes it easy to centralize and automate the backup of data across AWS services.
                
                To create a backup vault:
                
                1. Open the AWS Backup console: https://console.aws.amazon.com/backup/
                2. Choose Backup vaults
                3. Choose Create backup vault
                4. Enter a name for the vault
                5. Choose Create backup vault
                
                Learn more: https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault.html
                """,
                'message': 'No AWS Backup vaults found.'
            }
        
        # Process backup vaults
        vault_details = []
        for vault in backup_vaults:
            vault_details.append({
                'name': vault.get('BackupVaultName'),
                'arn': vault.get('BackupVaultArn'),
                'creation_date': str(vault.get('CreationDate')),
                'encryption_key_arn': vault.get('EncryptionKeyArn')
            })
        
        # Check if there are any backup plans
        try:
            plans_response = backup_client.list_backup_plans()
            backup_plans = plans_response.get('BackupPlansList', [])
            
            return {
                'enabled': True,
                'backup_vaults': vault_details,
                'backup_plans_count': len(backup_plans),
                'message': f'Found {len(backup_vaults)} AWS Backup vaults and {len(backup_plans)} backup plans.'
            }
        except Exception as plans_error:
            await ctx.warning(f'Error listing backup plans: {plans_error}')
            return {
                'enabled': True,
                'backup_vaults': vault_details,
                'message': f'Found {len(backup_vaults)} AWS Backup vaults. Error listing backup plans.'
            }
    except Exception as e:
        await ctx.error(f'Error checking AWS Backup vaults: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking AWS Backup vaults.'
        }


async def get_trusted_advisor_checks(
    region: str, 
    session: boto3.Session, 
    ctx: Context, 
    categories: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None
) -> Dict:
    """Get reliability-related checks from AWS Trusted Advisor.
    
    Args:
        region: AWS region to get checks from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        categories: Optional list of categories to filter by
        risk_levels: Optional list of risk levels to filter by
        
    Returns:
        Dictionary containing Trusted Advisor checks
    """
    try:
        # Trusted Advisor is only available in us-east-1
        if region != 'us-east-1':
            return {
                'message': 'Trusted Advisor is a global service, checked in us-east-1 region only.',
                'checks': []
            }
        
        # Create Support client
        support_client = session.client('support', region_name='us-east-1')
        
        # Get list of available checks
        checks_response = support_client.describe_trusted_advisor_checks(language='en')
        all_checks = checks_response.get('checks', [])
        
        # Filter checks by category if specified
        if categories:
            filtered_checks = [
                check for check in all_checks 
                if check.get('category') in categories
            ]
        else:
            # Default to reliability-related categories
            reliability_categories = [
                'fault_tolerance', 
                'performance', 
                'service_limits',
                'cost_optimizing'  # Some cost checks are also reliability-related
            ]
            filtered_checks = [
                check for check in all_checks 
                if check.get('category') in reliability_categories
            ]
        
        # Get check results
        check_ids = [check.get('id') for check in filtered_checks]
        check_results = []
        
        for check_id in check_ids:
            try:
                result = support_client.describe_trusted_advisor_check_result(
                    checkId=check_id,
                    language='en'
                )
                
                # Add check metadata
                check_metadata = next((c for c in filtered_checks if c.get('id') == check_id), {})
                result['result']['name'] = check_metadata.get('name')
                result['result']['category'] = check_metadata.get('category')
                result['result']['description'] = check_metadata.get('description')
                
                check_results.append(result.get('result', {}))
            except Exception as check_error:
                await ctx.warning(f'Error getting result for check {check_id}: {check_error}')
        
        # Filter by risk level if specified
        if risk_levels:
            check_results = [
                check for check in check_results 
                if check.get('status') in risk_levels
            ]
        
        # Generate summary
        summary = {
            'total_checks': len(check_results),
            'status_counts': {
                'error': len([c for c in check_results if c.get('status') == 'error']),
                'warning': len([c for c in check_results if c.get('status') == 'warning']),
                'ok': len([c for c in check_results if c.get('status') == 'ok']),
                'not_available': len([c for c in check_results if c.get('status') == 'not_available'])
            },
            'category_counts': {}
        }
        
        # Count by category
        for check in check_results:
            category = check.get('category', 'unknown')
            if category in summary['category_counts']:
                summary['category_counts'][category] += 1
            else:
                summary['category_counts'][category] = 1
        
        return {
            'message': f'Retrieved {len(check_results)} Trusted Advisor checks',
            'checks': check_results,
            'summary': summary
        }
    except Exception as e:
        await ctx.error(f'Error getting Trusted Advisor checks: {e}')
        return {
            'error': str(e),
            'message': 'Error getting Trusted Advisor checks',
            'checks': []
        }


async def get_resilience_hub_assessments(
    region: str, 
    session: boto3.Session, 
    ctx: Context, 
    app_arn: Optional[str] = None,
    max_results: int = 100
) -> Dict:
    """Get assessments from AWS Resilience Hub.
    
    Args:
        region: AWS region to get assessments from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        app_arn: Optional ARN of a specific application to get assessments for
        max_results: Maximum number of results to return
        
    Returns:
        Dictionary containing Resilience Hub assessments
    """
    try:
        # Create Resilience Hub client
        resiliencehub_client = session.client('resiliencehub', region_name=region)
        
        # If app_arn is not provided, list all applications
        if not app_arn:
            try:
                apps_response = resiliencehub_client.list_apps(maxResults=max_results)
                apps = apps_response.get('appSummaries', [])
                
                if not apps:
                    return {
                        'message': 'No applications found in AWS Resilience Hub',
                        'applications': [],
                        'assessments': []
                    }
                
                # Get assessments for each application
                all_assessments = []
                app_details = []
                
                for app in apps:
                    app_arn = app.get('appArn')
                    if not app_arn:
                        continue
                    
                    # Get application details
                    try:
                        app_response = resiliencehub_client.describe_app(appArn=app_arn)
                        app_details.append(app_response.get('app', {}))
                    except Exception as app_error:
                        await ctx.warning(f'Error getting details for application {app_arn}: {app_error}')
                        app_details.append(app)
                    
                    # Get assessments for this application
                    try:
                        assessments_response = resiliencehub_client.list_app_assessments(
                            appArn=app_arn,
                            maxResults=max_results
                        )
                        
                        app_assessments = assessments_response.get('assessmentSummaries', [])
                        
                        for assessment in app_assessments:
                            assessment_arn = assessment.get('assessmentArn')
                            if not assessment_arn:
                                continue
                            
                            # Get assessment details
                            try:
                                assessment_response = resiliencehub_client.describe_app_assessment(
                                    assessmentArn=assessment_arn
                                )
                                all_assessments.append(assessment_response.get('assessment', {}))
                            except Exception as assessment_error:
                                await ctx.warning(f'Error getting details for assessment {assessment_arn}: {assessment_error}')
                                all_assessments.append(assessment)
                    except Exception as assessments_error:
                        await ctx.warning(f'Error listing assessments for application {app_arn}: {assessments_error}')
                
                return {
                    'message': f'Retrieved {len(all_assessments)} assessments for {len(apps)} applications',
                    'applications': app_details,
                    'assessments': all_assessments
                }
            except Exception as apps_error:
                await ctx.error(f'Error listing applications: {apps_error}')
                return {
                    'error': str(apps_error),
                    'message': 'Error listing applications',
                    'applications': [],
                    'assessments': []
                }
        else:
            # Get assessments for the specified application
            try:
                # Get application details
                app_response = resiliencehub_client.describe_app(appArn=app_arn)
                app_details = app_response.get('app', {})
                
                # Get assessments for this application
                assessments_response = resiliencehub_client.list_app_assessments(
                    appArn=app_arn,
                    maxResults=max_results
                )
                
                app_assessments = assessments_response.get('assessmentSummaries', [])
                all_assessments = []
                
                for assessment in app_assessments:
                    assessment_arn = assessment.get('assessmentArn')
                    if not assessment_arn:
                        continue
                    
                    # Get assessment details
                    try:
                        assessment_response = resiliencehub_client.describe_app_assessment(
                            assessmentArn=assessment_arn
                        )
                        all_assessments.append(assessment_response.get('assessment', {}))
                    except Exception as assessment_error:
                        await ctx.warning(f'Error getting details for assessment {assessment_arn}: {assessment_error}')
                        all_assessments.append(assessment)
                
                return {
                    'message': f'Retrieved {len(all_assessments)} assessments for application {app_arn}',
                    'application': app_details,
                    'assessments': all_assessments
                }
            except Exception as app_error:
                await ctx.error(f'Error getting details for application {app_arn}: {app_error}')
                return {
                    'error': str(app_error),
                    'message': f'Error getting details for application {app_arn}',
                    'application': {},
                    'assessments': []
                }
    except Exception as e:
        await ctx.error(f'Error getting Resilience Hub assessments: {e}')
        return {
            'error': str(e),
            'message': 'Error getting Resilience Hub assessments',
            'applications': [],
            'assessments': []
        }


async def identify_reliability_gaps(
    region: str,
    session: boto3.Session,
    ctx: Context,
    resources: Dict,
    trusted_advisor_checks: Optional[Dict] = None,
    resilience_hub_assessments: Optional[Dict] = None
) -> Dict:
    """Identify gaps between current configuration and reliability best practices.
    
    Args:
        region: AWS region to analyze
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        resources: Dictionary of AWS resources to analyze
        trusted_advisor_checks: Optional dictionary of Trusted Advisor checks
        resilience_hub_assessments: Optional dictionary of Resilience Hub assessments
        
    Returns:
        Dictionary containing identified reliability gaps
    """
    try:
        gaps = []
        
        # Check for common reliability gaps
        
        # 1. Check for single AZ resources
        if 'ec2' in resources:
            # Check EC2 instances
            if 'instances' in resources['ec2']:
                instances = resources['ec2']['instances']
                
                # Group instances by AZ
                instances_by_az = {}
                for instance in instances:
                    az = instance.get('availability_zone')
                    if az:
                        if az in instances_by_az:
                            instances_by_az[az].append(instance)
                        else:
                            instances_by_az[az] = [instance]
                
                # If all instances are in a single AZ, that's a gap
                if len(instances_by_az) == 1:
                    gaps.append({
                        'category': 'high_availability',
                        'severity': 'HIGH',
                        'title': 'EC2 instances in single Availability Zone',
                        'description': 'All EC2 instances are deployed in a single Availability Zone, which creates a single point of failure.',
                        'affected_resources': [{'type': 'ec2_instance', 'id': instance.get('id')} for instance in instances],
                        'recommendation': 'Deploy EC2 instances across multiple Availability Zones to improve availability.'
                    })
        
        # 2. Check for RDS instances without Multi-AZ
        if 'rds' in resources:
            # Check RDS instances
            if 'db_instances' in resources['rds']:
                db_instances = resources['rds']['db_instances']
                
                # Find RDS instances without Multi-AZ
                single_az_dbs = [db for db in db_instances if not db.get('multi_az')]
                
                if single_az_dbs:
                    gaps.append({
                        'category': 'high_availability',
                        'severity': 'HIGH',
                        'title': 'RDS instances without Multi-AZ',
                        'description': f'Found {len(single_az_dbs)} RDS instances without Multi-AZ enabled, which creates a single point of failure.',
                        'affected_resources': [{'type': 'rds_instance', 'id': db.get('id')} for db in single_az_dbs],
                        'recommendation': 'Enable Multi-AZ for RDS instances to improve availability.'
                    })
        
        # 3. Check for missing CloudWatch alarms
        if not resources.get('cloudwatch', {}).get('alarms'):
            gaps.append({
                'category': 'monitoring',
                'severity': 'MEDIUM',
                'title': 'Missing CloudWatch alarms',
                'description': 'No CloudWatch alarms were found. CloudWatch alarms are essential for monitoring the health and performance of your resources.',
                'affected_resources': [],
                'recommendation': 'Create CloudWatch alarms for key metrics to monitor the health and performance of your resources.'
            })
        
        # 4. Check for missing Auto Scaling groups
        if not resources.get('autoscaling', {}).get('auto_scaling_groups'):
            gaps.append({
                'category': 'scalability',
                'severity': 'MEDIUM',
                'title': 'Missing Auto Scaling groups',
                'description': 'No Auto Scaling groups were found. Auto Scaling helps ensure that you have the correct number of Amazon EC2 instances available to handle the load for your application.',
                'affected_resources': [],
                'recommendation': 'Create Auto Scaling groups for your EC2 instances to improve scalability and availability.'
            })
        
        # 5. Check for missing load balancers
        if not resources.get('elb', {}).get('load_balancers'):
            gaps.append({
                'category': 'high_availability',
                'severity': 'MEDIUM',
                'title': 'Missing load balancers',
                'description': 'No load balancers were found. Load balancers distribute traffic across multiple targets, such as EC2 instances, to improve availability and fault tolerance.',
                'affected_resources': [],
                'recommendation': 'Deploy load balancers to distribute traffic across multiple targets.'
            })
        
        # 6. Check for missing Route 53 health checks
        if not resources.get('route53', {}).get('health_checks'):
            gaps.append({
                'category': 'monitoring',
                'severity': 'MEDIUM',
                'title': 'Missing Route 53 health checks',
                'description': 'No Route 53 health checks were found. Health checks are essential for monitoring the health and performance of your resources.',
                'affected_resources': [],
                'recommendation': 'Create Route 53 health checks for your endpoints to monitor their health and enable DNS failover.'
            })
        
        # 7. Check for missing AWS Backup vaults
        if not resources.get('backup', {}).get('backup_vaults'):
            gaps.append({
                'category': 'data_protection',
                'severity': 'HIGH',
                'title': 'Missing AWS Backup vaults',
                'description': 'No AWS Backup vaults were found. AWS Backup is a fully managed backup service that makes it easy to centralize and automate the backup of data across AWS services.',
                'affected_resources': [],
                'recommendation': 'Set up AWS Backup to protect your data and enable disaster recovery.'
            })
        
        # 8. Incorporate Trusted Advisor findings if available
        if trusted_advisor_checks and 'checks' in trusted_advisor_checks:
            for check in trusted_advisor_checks['checks']:
                if check.get('status') in ['error', 'warning']:
                    gaps.append({
                        'category': check.get('category', 'unknown'),
                        'severity': 'HIGH' if check.get('status') == 'error' else 'MEDIUM',
                        'title': check.get('name', 'Trusted Advisor Check'),
                        'description': check.get('description', 'No description available'),
                        'affected_resources': check.get('flaggedResources', []),
                        'recommendation': check.get('recommendedAction', 'No recommendation available')
                    })
        
        # 9. Incorporate Resilience Hub findings if available
        if resilience_hub_assessments and 'assessments' in resilience_hub_assessments:
            for assessment in resilience_hub_assessments['assessments']:
                if assessment.get('complianceStatus') != 'COMPLIANT':
                    gaps.append({
                        'category': 'resilience',
                        'severity': 'HIGH',
                        'title': f"Resilience Hub Assessment: {assessment.get('appVersion', 'Unknown')}",
                        'description': f"Application does not meet resilience policy requirements. Current RTO: {assessment.get('rtoDescription', 'Unknown')}, Current RPO: {assessment.get('rpoDescription', 'Unknown')}",
                        'affected_resources': [],
                        'recommendation': 'Review the Resilience Hub assessment and implement the recommended improvements.'
                    })
        
        # Generate summary
        summary = {
            'total_gaps': len(gaps),
            'severity_counts': {
                'high': len([g for g in gaps if g.get('severity') == 'HIGH']),
                'medium': len([g for g in gaps if g.get('severity') == 'MEDIUM']),
                'low': len([g for g in gaps if g.get('severity') == 'LOW'])
            },
            'category_counts': {}
        }
        
        # Count by category
        for gap in gaps:
            category = gap.get('category', 'unknown')
            if category in summary['category_counts']:
                summary['category_counts'][category] += 1
            else:
                summary['category_counts'][category] = 1
        
        return {
            'message': f'Identified {len(gaps)} reliability gaps',
            'gaps': gaps,
            'summary': summary
        }
    except Exception as e:
        await ctx.error(f'Error identifying reliability gaps: {e}')
        return {
            'error': str(e),
            'message': 'Error identifying reliability gaps',
            'gaps': []
        }
