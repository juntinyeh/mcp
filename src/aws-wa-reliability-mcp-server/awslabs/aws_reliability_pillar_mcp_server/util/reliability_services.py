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

"""Utility functions for AWS reliability services."""

import boto3
from typing import Dict, List, Any, Optional, Union
from loguru import logger
from mcp.server.fastmcp import Context
# Import constants from the consts module
from awslabs.aws_reliability_pillar_mcp_server.consts import (
    RELIABILITY_DOMAINS,
    RISK_LEVELS,
    TRUSTED_ADVISOR_RELIABILITY_CATEGORIES,
    RESILIENCE_HUB_COMPLIANCE_STATUSES,
    RELIABILITY_BEST_PRACTICES
)
from .resource_utils import list_resources_by_service


async def check_route53_health_checks(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Check the status of Route 53 health checks.
    
    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with health check status information
    """
    try:
        # Route 53 is a global service, but API calls must be made to us-east-1
        client = session.client('route53', region_name='us-east-1')
        
        # List health checks
        response = client.list_health_checks()
        health_checks = response.get('HealthChecks', [])
        
        # Check if any health checks exist
        if not health_checks:
            return {
                'enabled': False,
                'message': 'No Route 53 health checks found.',
                'recommendation': 'Consider configuring Route 53 health checks for critical resources to enable DNS failover.',
                'health_checks': []
            }
        
        # Process health checks
        health_check_details = []
        for health_check in health_checks:
            health_check_id = health_check['Id']
            
            # Get health check status
            try:
                status_response = client.get_health_check_status(HealthCheckId=health_check_id)
                health_status = status_response.get('HealthCheckObservations', [])
                
                # Determine overall status
                status_values = [obs.get('StatusReport', {}).get('Status') for obs in health_status]
                overall_status = 'Healthy' if all(status == 'Success' for status in status_values if status) else 'Unhealthy'
                
                health_check_details.append({
                    'id': health_check_id,
                    'type': health_check.get('HealthCheckConfig', {}).get('Type', 'Unknown'),
                    'status': overall_status,
                    'observations': len(health_status),
                    'config': health_check.get('HealthCheckConfig', {})
                })
            except Exception as e:
                await ctx.warning(f"Error getting status for health check {health_check_id}: {e}")
                health_check_details.append({
                    'id': health_check_id,
                    'type': health_check.get('HealthCheckConfig', {}).get('Type', 'Unknown'),
                    'status': 'Unknown',
                    'error': str(e),
                    'config': health_check.get('HealthCheckConfig', {})
                })
        
        # Determine if Route 53 health checks are effectively configured
        healthy_checks = len([hc for hc in health_check_details if hc['status'] == 'Healthy'])
        unhealthy_checks = len([hc for hc in health_check_details if hc['status'] == 'Unhealthy'])
        unknown_checks = len([hc for hc in health_check_details if hc['status'] == 'Unknown'])
        
        message = f"Found {len(health_checks)} Route 53 health checks: {healthy_checks} healthy, {unhealthy_checks} unhealthy, {unknown_checks} unknown."
        recommendation = ""
        
        if unhealthy_checks > 0:
            recommendation = "Investigate and resolve unhealthy health checks to ensure proper DNS failover."
        
        return {
            'enabled': True,
            'message': message,
            'recommendation': recommendation,
            'health_checks': health_check_details,
            'summary': {
                'total': len(health_checks),
                'healthy': healthy_checks,
                'unhealthy': unhealthy_checks,
                'unknown': unknown_checks
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error checking Route 53 health checks: {e}")
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Route 53 health checks.',
            'recommendation': 'Verify AWS credentials and permissions for Route 53.',
            'health_checks': []
        }


async def check_cloudwatch_alarms(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Check CloudWatch alarms configuration.
    
    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with CloudWatch alarms status information
    """
    try:
        client = session.client('cloudwatch', region_name=region)
        
        # List alarms
        response = client.describe_alarms()
        metric_alarms = response.get('MetricAlarms', [])
        composite_alarms = response.get('CompositeAlarms', [])
        
        total_alarms = len(metric_alarms) + len(composite_alarms)
        
        # Check if any alarms exist
        if total_alarms == 0:
            return {
                'enabled': False,
                'message': 'No CloudWatch alarms found.',
                'recommendation': 'Configure CloudWatch alarms for critical metrics to enable automated response to issues.',
                'alarms': []
            }
        
        # Process alarms
        alarm_details = []
        
        # Process metric alarms
        for alarm in metric_alarms:
            alarm_name = alarm['AlarmName']
            alarm_details.append({
                'name': alarm_name,
                'type': 'Metric',
                'state': alarm['StateValue'],
                'metric_name': alarm['MetricName'],
                'namespace': alarm['Namespace'],
                'statistic': alarm['Statistic'],
                'period': alarm['Period'],
                'threshold': alarm['Threshold'],
                'comparison_operator': alarm['ComparisonOperator'],
                'actions_enabled': alarm['ActionsEnabled'],
                'alarm_actions': alarm.get('AlarmActions', []),
                'ok_actions': alarm.get('OKActions', []),
                'insufficient_data_actions': alarm.get('InsufficientDataActions', [])
            })
        
        # Process composite alarms
        for alarm in composite_alarms:
            alarm_name = alarm['AlarmName']
            alarm_details.append({
                'name': alarm_name,
                'type': 'Composite',
                'state': alarm['StateValue'],
                'rule': alarm['AlarmRule'],
                'actions_enabled': alarm['ActionsEnabled'],
                'alarm_actions': alarm.get('AlarmActions', []),
                'ok_actions': alarm.get('OKActions', []),
                'insufficient_data_actions': alarm.get('InsufficientDataActions', [])
            })
        
        # Analyze alarm configuration
        alarms_with_actions = len([a for a in alarm_details if a.get('alarm_actions')])
        alarms_without_actions = total_alarms - alarms_with_actions
        
        alarm_states = {
            'OK': len([a for a in alarm_details if a['state'] == 'OK']),
            'ALARM': len([a for a in alarm_details if a['state'] == 'ALARM']),
            'INSUFFICIENT_DATA': len([a for a in alarm_details if a['state'] == 'INSUFFICIENT_DATA'])
        }
        
        message = f"Found {total_alarms} CloudWatch alarms: {alarm_states['OK']} OK, {alarm_states['ALARM']} in ALARM state, {alarm_states['INSUFFICIENT_DATA']} with insufficient data."
        recommendation = ""
        
        if alarms_without_actions > 0:
            recommendation = f"{alarms_without_actions} alarms do not have alarm actions configured. Consider adding actions to automate responses to issues."
        
        if alarm_states['ALARM'] > 0:
            if recommendation:
                recommendation += " "
            recommendation += f"{alarm_states['ALARM']} alarms are currently in ALARM state. Investigate and resolve these issues."
        
        return {
            'enabled': True,
            'message': message,
            'recommendation': recommendation,
            'alarms': alarm_details,
            'summary': {
                'total': total_alarms,
                'metric_alarms': len(metric_alarms),
                'composite_alarms': len(composite_alarms),
                'with_actions': alarms_with_actions,
                'without_actions': alarms_without_actions,
                'states': alarm_states
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error checking CloudWatch alarms: {e}")
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking CloudWatch alarms.',
            'recommendation': 'Verify AWS credentials and permissions for CloudWatch.',
            'alarms': []
        }


async def check_auto_scaling_groups(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Check Auto Scaling groups configuration.
    
    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with Auto Scaling groups status information
    """
    try:
        client = session.client('autoscaling', region_name=region)
        
        # List Auto Scaling groups
        response = client.describe_auto_scaling_groups()
        auto_scaling_groups = response.get('AutoScalingGroups', [])
        
        # Check if any Auto Scaling groups exist
        if not auto_scaling_groups:
            return {
                'enabled': False,
                'message': 'No Auto Scaling groups found.',
                'recommendation': 'Consider using Auto Scaling groups to improve availability and scalability.',
                'auto_scaling_groups': []
            }
        
        # Process Auto Scaling groups
        asg_details = []
        for asg in auto_scaling_groups:
            asg_name = asg['AutoScalingGroupName']
            
            # Check for scaling policies
            scaling_policies = []
            try:
                policies_response = client.describe_policies(AutoScalingGroupName=asg_name)
                scaling_policies = policies_response.get('ScalingPolicies', [])
            except Exception as e:
                await ctx.warning(f"Error getting scaling policies for ASG {asg_name}: {e}")
            
            # Check for scheduled actions
            scheduled_actions = []
            try:
                actions_response = client.describe_scheduled_actions(AutoScalingGroupName=asg_name)
                scheduled_actions = actions_response.get('ScheduledUpdateGroupActions', [])
            except Exception as e:
                await ctx.warning(f"Error getting scheduled actions for ASG {asg_name}: {e}")
            
            # Get availability zones
            availability_zones = asg.get('AvailabilityZones', [])
            
            asg_details.append({
                'name': asg_name,
                'min_size': asg['MinSize'],
                'max_size': asg['MaxSize'],
                'desired_capacity': asg['DesiredCapacity'],
                'availability_zones': availability_zones,
                'multi_az': len(availability_zones) > 1,
                'instances': len(asg.get('Instances', [])),
                'health_check_type': asg['HealthCheckType'],
                'health_check_grace_period': asg['HealthCheckGracePeriod'],
                'load_balancers': asg.get('LoadBalancerNames', []),
                'target_groups': asg.get('TargetGroupARNs', []),
                'scaling_policies': len(scaling_policies),
                'scheduled_actions': len(scheduled_actions)
            })
        
        # Analyze Auto Scaling group configuration
        multi_az_asgs = len([asg for asg in asg_details if asg['multi_az']])
        single_az_asgs = len(auto_scaling_groups) - multi_az_asgs
        
        asgs_with_elb_health_checks = len([asg for asg in asg_details if asg['health_check_type'] == 'ELB'])
        asgs_with_ec2_health_checks = len([asg for asg in asg_details if asg['health_check_type'] == 'EC2'])
        
        asgs_with_scaling_policies = len([asg for asg in asg_details if asg['scaling_policies'] > 0])
        asgs_without_scaling_policies = len(auto_scaling_groups) - asgs_with_scaling_policies
        
        message = f"Found {len(auto_scaling_groups)} Auto Scaling groups: {multi_az_asgs} multi-AZ, {single_az_asgs} single-AZ."
        recommendation = ""
        
        if single_az_asgs > 0:
            recommendation = f"{single_az_asgs} Auto Scaling groups are configured with a single Availability Zone. Consider using multiple AZs for higher availability."
        
        if asgs_with_ec2_health_checks > 0 and asgs_with_elb_health_checks > 0:
            if recommendation:
                recommendation += " "
            recommendation += f"{asgs_with_ec2_health_checks} Auto Scaling groups are using EC2 health checks. Consider using ELB health checks for more comprehensive health monitoring."
        
        if asgs_without_scaling_policies > 0:
            if recommendation:
                recommendation += " "
            recommendation += f"{asgs_without_scaling_policies} Auto Scaling groups do not have scaling policies. Consider adding scaling policies to automatically adjust capacity based on demand."
        
        return {
            'enabled': True,
            'message': message,
            'recommendation': recommendation,
            'auto_scaling_groups': asg_details,
            'summary': {
                'total': len(auto_scaling_groups),
                'multi_az': multi_az_asgs,
                'single_az': single_az_asgs,
                'elb_health_checks': asgs_with_elb_health_checks,
                'ec2_health_checks': asgs_with_ec2_health_checks,
                'with_scaling_policies': asgs_with_scaling_policies,
                'without_scaling_policies': asgs_without_scaling_policies
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error checking Auto Scaling groups: {e}")
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Auto Scaling groups.',
            'recommendation': 'Verify AWS credentials and permissions for Auto Scaling.',
            'auto_scaling_groups': []
        }


async def check_load_balancers(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Check Load Balancers configuration.
    
    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with Load Balancers status information
    """
    try:
        # Check Classic Load Balancers
        elb_client = session.client('elb', region_name=region)
        classic_response = elb_client.describe_load_balancers()
        classic_lbs = classic_response.get('LoadBalancerDescriptions', [])
        
        # Check Application and Network Load Balancers
        elbv2_client = session.client('elbv2', region_name=region)
        elbv2_response = elbv2_client.describe_load_balancers()
        elbv2_lbs = elbv2_response.get('LoadBalancers', [])
        
        total_lbs = len(classic_lbs) + len(elbv2_lbs)
        
        # Check if any Load Balancers exist
        if total_lbs == 0:
            return {
                'enabled': False,
                'message': 'No Load Balancers found.',
                'recommendation': 'Consider using Elastic Load Balancing to improve availability and fault tolerance.',
                'load_balancers': []
            }
        
        # Process Load Balancers
        lb_details = []
        
        # Process Classic Load Balancers
        for lb in classic_lbs:
            lb_name = lb['LoadBalancerName']
            
            # Get availability zones
            availability_zones = lb.get('AvailabilityZones', [])
            
            # Get health check configuration
            health_check = lb.get('HealthCheck', {})
            
            lb_details.append({
                'name': lb_name,
                'type': 'classic',
                'dns_name': lb.get('DNSName', ''),
                'availability_zones': availability_zones,
                'multi_az': len(availability_zones) > 1,
                'vpc_id': lb.get('VPCId'),
                'instances': len(lb.get('Instances', [])),
                'health_check': {
                    'target': health_check.get('Target', ''),
                    'interval': health_check.get('Interval', 0),
                    'timeout': health_check.get('Timeout', 0),
                    'unhealthy_threshold': health_check.get('UnhealthyThreshold', 0),
                    'healthy_threshold': health_check.get('HealthyThreshold', 0)
                }
            })
        
        # Process Application and Network Load Balancers
        for lb in elbv2_lbs:
            lb_name = lb['LoadBalancerName']
            
            # Get availability zones
            availability_zones = lb.get('AvailabilityZones', [])
            
            # Get target groups
            target_groups = []
            try:
                tg_response = elbv2_client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                target_groups = tg_response.get('TargetGroups', [])
            except Exception as e:
                await ctx.warning(f"Error getting target groups for LB {lb_name}: {e}")
            
            lb_details.append({
                'name': lb_name,
                'type': lb['Type'].lower(),
                'dns_name': lb.get('DNSName', ''),
                'availability_zones': [az['ZoneName'] for az in availability_zones],
                'multi_az': len(availability_zones) > 1,
                'vpc_id': lb.get('VpcId'),
                'target_groups': len(target_groups),
                'scheme': lb.get('Scheme', 'internet-facing')
            })
        
        # Analyze Load Balancer configuration
        multi_az_lbs = len([lb for lb in lb_details if lb.get('multi_az', False)])
        single_az_lbs = total_lbs - multi_az_lbs
        
        lb_types = {
            'classic': len([lb for lb in lb_details if lb['type'] == 'classic']),
            'application': len([lb for lb in lb_details if lb['type'] == 'application']),
            'network': len([lb for lb in lb_details if lb['type'] == 'network'])
        }
        
        message = f"Found {total_lbs} Load Balancers: {lb_types['classic']} Classic, {lb_types['application']} Application, {lb_types['network']} Network."
        recommendation = ""
        
        if single_az_lbs > 0:
            recommendation = f"{single_az_lbs} Load Balancers are configured with a single Availability Zone. Consider using multiple AZs for higher availability."
        
        if lb_types['classic'] > 0:
            if recommendation:
                recommendation += " "
            recommendation += f"{lb_types['classic']} Classic Load Balancers detected. Consider migrating to Application or Network Load Balancers for advanced features and improved performance."
        
        return {
            'enabled': True,
            'message': message,
            'recommendation': recommendation,
            'load_balancers': lb_details,
            'summary': {
                'total': total_lbs,
                'multi_az': multi_az_lbs,
                'single_az': single_az_lbs,
                'types': lb_types
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error checking Load Balancers: {e}")
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Load Balancers.',
            'recommendation': 'Verify AWS credentials and permissions for Elastic Load Balancing.',
            'load_balancers': []
        }


async def check_backup_vaults(
    region: str,
    session: boto3.Session,
    ctx: Context
) -> Dict[str, Any]:
    """Check AWS Backup vaults configuration.
    
    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with AWS Backup vaults status information
    """
    try:
        client = session.client('backup', region_name=region)
        
        # List backup vaults
        response = client.list_backup_vaults()
        backup_vaults = response.get('BackupVaultList', [])
        
        # Check if any backup vaults exist
        if not backup_vaults:
            return {
                'enabled': False,
                'message': 'No AWS Backup vaults found.',
                'recommendation': 'Consider using AWS Backup to centrally manage and automate data protection across AWS services.',
                'backup_vaults': []
            }
        
        # Process backup vaults
        vault_details = []
        for vault in backup_vaults:
            vault_name = vault['BackupVaultName']
            
            # Get recovery points (backups) in the vault
            recovery_points_count = 0
            try:
                recovery_points_response = client.list_recovery_points_by_backup_vault(
                    BackupVaultName=vault_name,
                    MaxResults=1  # Just to check if there are any recovery points
                )
                recovery_points_count = recovery_points_response.get('NumberOfRecoveryPoints', 0)
            except Exception as e:
                await ctx.warning(f"Error getting recovery points for vault {vault_name}: {e}")
            
            vault_details.append({
                'name': vault_name,
                'arn': vault['BackupVaultArn'],
                'creation_date': str(vault['CreationDate']),
                'encryption_key_arn': vault.get('EncryptionKeyArn'),
                'recovery_points': recovery_points_count
            })
        
        # List backup plans
        backup_plans = []
        try:
            plans_response = client.list_backup_plans()
            backup_plans = plans_response.get('BackupPlansList', [])
        except Exception as e:
            await ctx.warning(f"Error listing backup plans: {e}")
        
        # Process backup plans
        plan_details = []
        for plan in backup_plans:
            plan_name = plan['BackupPlanName']
            
            # Get backup plan details
            try:
                plan_response = client.get_backup_plan(
                    BackupPlanId=plan['BackupPlanId']
                )
                
                backup_plan = plan_response.get('BackupPlan', {})
                rules = backup_plan.get('Rules', [])
                
                plan_details.append({
                    'name': plan_name,
                    'id': plan['BackupPlanId'],
                    'version_id': plan['VersionId'],
                    'creation_date': str(plan['CreationDate']),
                    'rules_count': len(rules),
                    'rules': [
                        {
                            'name': rule.get('RuleName', ''),
                            'target_vault': rule.get('TargetBackupVaultName', ''),
                            'schedule': rule.get('ScheduleExpression', ''),
                            'lifecycle': rule.get('Lifecycle', {})
                        }
                        for rule in rules
                    ]
                })
            except Exception as e:
                await ctx.warning(f"Error getting details for backup plan {plan_name}: {e}")
                plan_details.append({
                    'name': plan_name,
                    'id': plan['BackupPlanId'],
                    'version_id': plan['VersionId'],
                    'creation_date': str(plan['CreationDate']),
                    'error': str(e)
                })
        
        # Analyze backup configuration
        vaults_with_backups = len([v for v in vault_details if v['recovery_points'] > 0])
        vaults_without_backups = len(backup_vaults) - vaults_with_backups
        
        message = f"Found {len(backup_vaults)} AWS Backup vaults and {len(backup_plans)} backup plans."
        recommendation = ""
        
        if vaults_without_backups > 0:
            recommendation = f"{vaults_without_backups} backup vaults do not have any recovery points. Verify that backup plans are correctly configured."
        
        if not backup_plans:
            if recommendation:
                recommendation += " "
            recommendation += "No backup plans found. Consider creating backup plans to automate backup of your resources."
        
        return {
            'enabled': True,
            'message': message,
            'recommendation': recommendation,
            'backup_vaults': vault_details,
            'backup_plans': plan_details,
            'summary': {
                'total_vaults': len(backup_vaults),
                'vaults_with_backups': vaults_with_backups,
                'vaults_without_backups': vaults_without_backups,
                'total_plans': len(backup_plans)
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error checking AWS Backup vaults: {e}")
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking AWS Backup vaults.',
            'recommendation': 'Verify AWS credentials and permissions for AWS Backup.',
            'backup_vaults': []
        }


async def get_resilience_hub_assessments(
    region: str,
    session: boto3.Session,
    ctx: Context,
    app_arn: Optional[str] = None,
    max_results: int = 100
) -> Dict[str, Any]:
    """Retrieve assessments from AWS Resilience Hub.
    
    Args:
        region: AWS region to retrieve assessments from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        app_arn: Optional ARN of a specific application to get assessments for
        max_results: Maximum number of results to retrieve
        
    Returns:
        Dictionary with Resilience Hub assessments information
    """
    try:
        client = session.client('resiliencehub', region_name=region)
        
        # Check if Resilience Hub is available in the region
        try:
            # List applications
            if app_arn:
                # If app_arn is provided, get details for that specific application
                app_response = client.describe_app(
                    appArn=app_arn
                )
                applications = [app_response] if 'app' in app_response else []
            else:
                # Otherwise, list all applications
                apps_response = client.list_apps(
                    maxResults=max_results
                )
                applications = apps_response.get('appSummaries', [])
            
            if not applications:
                return {
                    'message': 'No applications found in AWS Resilience Hub.',
                    'recommendation': 'Consider using AWS Resilience Hub to assess and improve your application resiliency.',
                    'applications': [],
                    'assessments': []
                }
        except Exception as e:
            error_message = str(e)
            if 'AccessDeniedException' in error_message:
                return {
                    'message': 'Access denied to AWS Resilience Hub.',
                    'recommendation': 'Verify AWS credentials and permissions for AWS Resilience Hub.',
                    'applications': [],
                    'assessments': []
                }
            else:
                raise e
        
        # Get assessments for each application
        all_assessments = []
        for app in applications:
            app_arn = app.get('appArn', '')
            if not app_arn:
                continue
            
            try:
                # List assessments for the application
                assessments_response = client.list_app_assessments(
                    appArn=app_arn,
                    maxResults=max_results
                )
                
                app_assessments = assessments_response.get('assessmentSummaries', [])
                
                # Get detailed assessment information
                for assessment in app_assessments:
                    assessment_arn = assessment.get('assessmentArn', '')
                    if not assessment_arn:
                        continue
                    
                    try:
                        # Get assessment details
                        assessment_response = client.describe_app_assessment(
                            assessmentArn=assessment_arn
                        )
                        
                        assessment_details = assessment_response.get('assessment', {})
                        if assessment_details:
                            all_assessments.append(assessment_details)
                    except Exception as e:
                        await ctx.warning(f"Error getting details for assessment {assessment_arn}: {e}")
            except Exception as e:
                await ctx.warning(f"Error listing assessments for application {app_arn}: {e}")
        
        # Analyze assessment results
        compliance_status_counts = {}
        for assessment in all_assessments:
            status = assessment.get('complianceStatus', 'UNKNOWN')
            if status not in compliance_status_counts:
                compliance_status_counts[status] = 0
            compliance_status_counts[status] += 1
        
        message = f"Found {len(applications)} applications and {len(all_assessments)} assessments in AWS Resilience Hub."
        recommendation = ""
        
        if len(all_assessments) == 0:
            recommendation = "No assessments found. Consider running assessments in AWS Resilience Hub to evaluate your application resiliency."
        elif 'NON_COMPLIANT' in compliance_status_counts:
            recommendation = f"Found {compliance_status_counts.get('NON_COMPLIANT', 0)} non-compliant assessments. Review and address the issues identified by AWS Resilience Hub."
        
        return {
            'applications': applications,
            'assessments': all_assessments,
            'message': message,
            'recommendation': recommendation,
            'summary': {
                'total_applications': len(applications),
                'total_assessments': len(all_assessments),
                'compliance_status_counts': compliance_status_counts
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error getting Resilience Hub assessments: {e}")
        return {
            'error': str(e),
            'message': 'Error getting Resilience Hub assessments.',
            'recommendation': 'Verify AWS credentials and permissions for AWS Resilience Hub.',
            'applications': [],
            'assessments': []
        }


async def identify_reliability_gaps(
    region: str,
    session: boto3.Session,
    ctx: Context,
    resources: Dict[str, Any],
    trusted_advisor_checks: Optional[Dict[str, Any]] = None,
    resilience_hub_assessments: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Identify gaps between current configuration and reliability best practices.
    
    Args:
        region: AWS region to analyze
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        resources: Dictionary of resources by service
        trusted_advisor_checks: Optional Trusted Advisor checks
        resilience_hub_assessments: Optional Resilience Hub assessments
        
    Returns:
        Dictionary with identified reliability gaps
    """
    try:
        print(f"Identifying reliability gaps in region {region}...")
        
        # Initialize gaps list
        gaps = []
        
        # Check for multi-AZ deployments in EC2 instances
        if 'ec2' in resources:
            ec2_instances = resources.get('ec2', {}).get('instances', [])
            
            # Group instances by availability zone
            instances_by_az = {}
            for instance in ec2_instances:
                az = instance.get('placement', {}).get('availability_zone', 'unknown')
                if az not in instances_by_az:
                    instances_by_az[az] = []
                instances_by_az[az].append(instance)
            
            # Check if instances are spread across multiple AZs
            if len(instances_by_az) == 1 and len(ec2_instances) > 1:
                gaps.append({
                    'category': 'High Availability',
                    'title': 'EC2 instances not spread across multiple Availability Zones',
                    'description': f"All {len(ec2_instances)} EC2 instances are deployed in a single Availability Zone ({list(instances_by_az.keys())[0]}).",
                    'recommendation': 'Deploy EC2 instances across multiple Availability Zones to improve availability and fault tolerance.',
                    'severity': 'HIGH',
                    'affected_resources': [instance.get('instance_id', '') for instance in ec2_instances]
                })
        
        # Check for RDS multi-AZ configuration
        if 'rds' in resources:
            rds_instances = resources.get('rds', {}).get('db_instances', [])
            
            # Check if RDS instances have multi-AZ enabled
            single_az_rds = [
                instance for instance in rds_instances
                if not instance.get('multi_az', False)
            ]
            
            if single_az_rds:
                gaps.append({
                    'category': 'High Availability',
                    'title': 'RDS instances not configured for Multi-AZ',
                    'description': f"{len(single_az_rds)} RDS instances are not configured for Multi-AZ deployment.",
                    'recommendation': 'Enable Multi-AZ for RDS instances to improve availability and fault tolerance.',
                    'severity': 'MEDIUM',
                    'affected_resources': [instance.get('db_instance_identifier', '') for instance in single_az_rds]
                })
        
        # Check for S3 bucket versioning
        if 's3' in resources:
            s3_buckets = resources.get('s3', {}).get('buckets', [])
            
            # Check if S3 buckets have versioning enabled
            buckets_without_versioning = [
                bucket for bucket in s3_buckets
                if not bucket.get('versioning', {}).get('status') == 'Enabled'
            ]
            
            if buckets_without_versioning:
                gaps.append({
                    'category': 'Data Protection',
                    'title': 'S3 buckets without versioning enabled',
                    'description': f"{len(buckets_without_versioning)} S3 buckets do not have versioning enabled.",
                    'recommendation': 'Enable versioning for S3 buckets to protect against accidental deletion and provide data recovery capabilities.',
                    'severity': 'MEDIUM',
                    'affected_resources': [bucket.get('name', '') for bucket in buckets_without_versioning]
                })
        
        # Check for DynamoDB backup configuration
        if 'dynamodb' in resources:
            dynamodb_tables = resources.get('dynamodb', {}).get('tables', [])
            
            # Check if DynamoDB tables have point-in-time recovery enabled
            tables_without_pitr = [
                table for table in dynamodb_tables
                if not table.get('point_in_time_recovery', {}).get('status') == 'ENABLED'
            ]
            
            if tables_without_pitr:
                gaps.append({
                    'category': 'Data Protection',
                    'title': 'DynamoDB tables without point-in-time recovery enabled',
                    'description': f"{len(tables_without_pitr)} DynamoDB tables do not have point-in-time recovery enabled.",
                    'recommendation': 'Enable point-in-time recovery for DynamoDB tables to protect against accidental writes or deletes.',
                    'severity': 'MEDIUM',
                    'affected_resources': [table.get('table_name', '') for table in tables_without_pitr]
                })
        
        # Check for CloudWatch alarms for critical metrics
        if 'cloudwatch' in resources:
            cloudwatch_alarms = resources.get('cloudwatch', {}).get('alarms', [])
            
            # Check if there are alarms for critical metrics
            critical_metrics = [
                'CPUUtilization',
                'MemoryUtilization',
                'DiskSpaceUtilization',
                'StatusCheckFailed',
                'HTTPCode_ELB_5XX_Count',
                'HTTPCode_Target_5XX_Count'
            ]
            
            metrics_with_alarms = set()
            for alarm in cloudwatch_alarms:
                metric_name = alarm.get('metric_name', '')
                if metric_name in critical_metrics:
                    metrics_with_alarms.add(metric_name)
            
            missing_critical_alarms = [metric for metric in critical_metrics if metric not in metrics_with_alarms]
            
            if missing_critical_alarms:
                gaps.append({
                    'category': 'Monitoring',
                    'title': 'Missing CloudWatch alarms for critical metrics',
                    'description': f"No CloudWatch alarms found for these critical metrics: {', '.join(missing_critical_alarms)}.",
                    'recommendation': 'Configure CloudWatch alarms for critical metrics to enable automated response to issues.',
                    'severity': 'MEDIUM',
                    'affected_resources': []
                })
        
        # Incorporate Trusted Advisor findings if available
        if trusted_advisor_checks and 'checks' in trusted_advisor_checks:
            for check in trusted_advisor_checks['checks']:
                if check['status'].lower() in ['warning', 'error']:
                    # Only include reliability-related checks
                    if any(category.lower() in check.get('category', '').lower() for category in TRUSTED_ADVISOR_RELIABILITY_CATEGORIES):
                        severity = 'HIGH' if check['status'].lower() == 'error' else 'MEDIUM'
                        
                        # Filter resources to only include those in the current region
                        regional_resources = [
                            resource['resource_id'] for resource in check.get('resources', [])
                            if resource.get('region', 'global') == region or resource.get('region', 'global') == 'global'
                        ]
                        
                        if regional_resources:
                            gaps.append({
                                'category': 'Trusted Advisor',
                                'title': check.get('name', 'Trusted Advisor finding'),
                                'description': check.get('description', 'No description available'),
                                'recommendation': 'Review and address the issue identified by AWS Trusted Advisor.',
                                'severity': severity,
                                'affected_resources': regional_resources
                            })
        
        # Incorporate Resilience Hub findings if available
        if resilience_hub_assessments and 'assessments' in resilience_hub_assessments:
            for assessment in resilience_hub_assessments['assessments']:
                if assessment.get('complianceStatus', '') == 'NON_COMPLIANT':
                    # Extract recommendations from the assessment
                    app_components = assessment.get('appComponents', [])
                    for component in app_components:
                        recommendations = component.get('recommendations', [])
                        for recommendation in recommendations:
                            gaps.append({
                                'category': 'Resilience Hub',
                                'title': f"Resilience issue in {component.get('name', 'component')}",
                                'description': recommendation.get('description', 'No description available'),
                                'recommendation': recommendation.get('recommendation', 'Review and address the issue identified by AWS Resilience Hub.'),
                                'severity': 'MEDIUM',
                                'affected_resources': [component.get('id', '')]
                            })
        
        # Analyze gaps by category and severity
        gaps_by_category = {}
        gaps_by_severity = {
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for gap in gaps:
            category = gap.get('category', 'unknown')
            severity = gap.get('severity', 'MEDIUM')
            
            if category not in gaps_by_category:
                gaps_by_category[category] = 0
            
            gaps_by_category[category] += 1
            gaps_by_severity[severity] += 1
        
        # Generate summary message
        message = f"Found {len(gaps)} reliability gaps in region {region}."
        recommendation = ""
        
        if gaps_by_severity['HIGH'] > 0:
            recommendation = f"Address {gaps_by_severity['HIGH']} high-severity issues to improve reliability."
        
        return {
            'gaps': gaps,
            'message': message,
            'recommendation': recommendation,
            'summary': {
                'total': len(gaps),
                'by_category': gaps_by_category,
                'by_severity': gaps_by_severity
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error identifying reliability gaps: {e}")
        return {
            'error': str(e),
            'message': 'Error identifying reliability gaps.',
            'recommendation': 'Verify AWS credentials and permissions.',
            'gaps': []
        }


async def get_trusted_advisor_checks(
    region: str,
    session: boto3.Session,
    ctx: Context,
    categories: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Retrieve reliability-related checks from AWS Trusted Advisor.
    
    Args:
        region: AWS region to retrieve checks from (Trusted Advisor is global)
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        categories: Optional list of categories to filter by
        risk_levels: Optional list of risk levels to filter by
        
    Returns:
        Dictionary with Trusted Advisor checks information
    """
    try:
        # Trusted Advisor API calls must be made to us-east-1
        client = session.client('support', region_name='us-east-1')
        
        # Check if Trusted Advisor is available (requires Business or Enterprise Support)
        try:
            # List available checks
            checks_response = client.describe_trusted_advisor_checks(language='en')
            available_checks = checks_response.get('checks', [])
            
            if not available_checks:
                return {
                    'message': 'No Trusted Advisor checks available.',
                    'recommendation': 'Trusted Advisor requires Business or Enterprise Support plan.',
                    'checks': []
                }
        except Exception as e:
            error_message = str(e)
            if 'SubscriptionRequiredException' in error_message:
                return {
                    'message': 'Trusted Advisor is not available with your support plan.',
                    'recommendation': 'Upgrade to Business or Enterprise Support to access Trusted Advisor.',
                    'checks': []
                }
            else:
                raise e
        
        # Filter checks by category if specified
        if categories:
            filtered_checks = [
                check for check in available_checks
                if any(category.lower() in check.get('category', '').lower() for category in categories)
            ]
        else:
            # Default to reliability-related categories
            filtered_checks = [
                check for check in available_checks
                if any(category.lower() in check.get('category', '').lower() for category in TRUSTED_ADVISOR_RELIABILITY_CATEGORIES)
            ]
        
        # Get check results
        check_results = []
        for check in filtered_checks:
            check_id = check['id']
            
            try:
                result_response = client.describe_trusted_advisor_check_result(
                    checkId=check_id,
                    language='en'
                )
                
                result = result_response.get('result', {})
                status = result.get('status', 'unknown')
                
                # Filter by risk level if specified
                if risk_levels and status.lower() not in [level.lower() for level in risk_levels]:
                    continue
                
                # Process resources
                resources = []
                for resource in result.get('flaggedResources', []):
                    resources.append({
                        'status': resource.get('status', 'unknown'),
                        'region': resource.get('region', 'global'),
                        'resource_id': resource.get('resourceId', ''),
                        'metadata': resource.get('metadata', [])
                    })
                
                check_results.append({
                    'id': check_id,
                    'name': check.get('name', ''),
                    'description': check.get('description', ''),
                    'category': check.get('category', ''),
                    'status': status,
                    'resource_count': len(resources),
                    'resources': resources,
                    'timestamp': result.get('timestamp', '')
                })
            except Exception as e:
                await ctx.warning(f"Error getting result for check {check_id}: {e}")
        
        # Analyze check results
        status_counts = {
            'ok': len([c for c in check_results if c['status'].lower() == 'ok']),
            'warning': len([c for c in check_results if c['status'].lower() == 'warning']),
            'error': len([c for c in check_results if c['status'].lower() == 'error'])
        }
        
        message = f"Found {len(check_results)} Trusted Advisor checks: {status_counts['ok']} OK, {status_counts['warning']} warnings, {status_counts['error']} errors."
        recommendation = ""
        
        if status_counts['error'] > 0:
            recommendation = f"Address {status_counts['error']} critical issues identified by Trusted Advisor."
        
        if status_counts['warning'] > 0:
            if recommendation:
                recommendation += " "
            recommendation += f"Review {status_counts['warning']} warnings identified by Trusted Advisor."
        
        return {
            'checks': check_results,
            'message': message,
            'recommendation': recommendation,
            'summary': {
                'total': len(check_results),
                'status_counts': status_counts,
                'categories': {
                    category: len([c for c in check_results if c['category'] == category])
                    for category in set(c['category'] for c in check_results if 'category' in c)
                }
            }
        }
    
    except Exception as e:
        await ctx.error(f"Error getting Trusted Advisor checks: {e}")
        return {
            'error': str(e),
            'message': 'Error getting Trusted Advisor checks.',
            'recommendation': 'Verify AWS credentials and permissions for AWS Support.',
            'checks': []
        }
