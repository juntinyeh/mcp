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

"""AWS Reliability Pillar MCP Server implementation."""

import argparse
import os
import sys
import datetime
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP
from typing import Dict, List, Optional, Any, Literal
from pydantic import Field
import boto3
import asyncio

# Set up AWS region and profile from environment variables
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_PROFILE = os.environ.get('AWS_PROFILE', 'default')

# Import local modules
from awslabs.aws_reliability_pillar_mcp_server.util.reliability_services import (
    check_route53_health_checks,
    check_cloudwatch_alarms,
    check_auto_scaling_groups,
    check_load_balancers,
    check_backup_vaults,
    get_trusted_advisor_checks,
    get_resilience_hub_assessments,
    identify_reliability_gaps,
)
from awslabs.aws_reliability_pillar_mcp_server.util.resource_utils import (
    list_resources_by_service,
    list_all_resources,
    resource_inventory_summary,
    get_tagged_resources,
    get_resource_compliance_status,
)

# Import constants
from awslabs.aws_reliability_pillar_mcp_server.consts import (
    SERVICE_DESCRIPTIONS,
    RELIABILITY_DOMAINS,
    RISK_LEVELS,
    TRUSTED_ADVISOR_RELIABILITY_CATEGORIES,
    RESILIENCE_HUB_COMPLIANCE_STATUSES,
)

# Remove default logger and add custom configuration
logger.remove()
logger.add(sys.stderr, level=os.getenv("FASTMCP_LOG_LEVEL", "DEBUG"))

# Initialize MCP Server
mcp = FastMCP(
    "aws-reliability-pillar-mcp-server",
    dependencies=[
        'boto3', 
        'requests', 
        'beautifulsoup4',
        'pydantic',
        'loguru',
    ],
)

# Global context storage for sharing data between tool calls
context_storage = {}

async def initialize():
    """Initialize shared components on startup.
    
    This function loads and initializes any shared components
    that will be used throughout the server's operation. If initialization fails,
    the components will be loaded on demand when needed.
    """
    try:
        # Import core components if needed
        # from knowledge.reliability_patterns import ReliabilityPatternCatalog
        # from rules.rule_catalog import RuleCatalog
        
        # These components will be implemented later
        # reliability_pattern_catalog = ReliabilityPatternCatalog()
        # await reliability_pattern_catalog.initialize()
        
        # rule_catalog = RuleCatalog()
        # await rule_catalog.initialize()
        
        logger.info("AWS Reliability Pillar MCP Server initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing AWS Reliability Pillar MCP Server: {e}")
        # Continue without initialization - components will be loaded on demand

@mcp.tool(name='CheckReliabilityServices')
async def check_reliability_services(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region to check for reliability services status"
    ),
    services: List[str] = Field(
        ['route53', 'cloudwatch', 'autoscaling', 'elb', 'backup'], 
        description="List of reliability services to check. Options: route53, cloudwatch, autoscaling, elb, backup"
    ),
    account_id: Optional[str] = Field(
        None, 
        description="Optional AWS account ID (defaults to caller's account)"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable or 'default')"
    ),
    store_in_context: bool = Field(
        True,
        description="Whether to store results in context for access by other tools"
    ),
    debug: bool = Field(
        True,
        description="Whether to include detailed debug information in the response"
    )
) -> Dict:
    """Verify if selected AWS reliability services are properly configured in the specified region and account.

    This consolidated tool checks the status of multiple AWS reliability services in a single call,
    providing a comprehensive overview of your reliability posture.
    
    ## Response format
    Returns a dictionary with:
    - region: The region that was checked
    - services_checked: List of services that were checked
    - all_configured: Boolean indicating if all specified services are properly configured
    - service_statuses: Dictionary with detailed status for each service
    - summary: Summary of reliability recommendations
    
    ## AWS permissions required
    - route53:ListHealthChecks (if checking Route 53)
    - cloudwatch:DescribeAlarms (if checking CloudWatch)
    - autoscaling:DescribeAutoScalingGroups (if checking Auto Scaling)
    - elasticloadbalancing:DescribeLoadBalancers (if checking ELB)
    - backup:ListBackupVaults (if checking AWS Backup)
    """
    try:
        # Start timestamp for measuring execution time
        start_time = datetime.datetime.now()
        
        if debug:
            print(f"[DEBUG:CheckReliabilityServices] Starting reliability services check for region: {region}")
            print(f"[DEBUG:CheckReliabilityServices] Services to check: {', '.join(services)}")
            print(f"[DEBUG:CheckReliabilityServices] Using AWS profile: {aws_profile or 'default'}")
        
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Initialize results
        results = {
            'region': region,
            'services_checked': services,
            'all_configured': True,
            'service_statuses': {}
        }
        
        if debug:
            # Add debug info to the results
            results['debug_info'] = {
                'start_time': start_time.isoformat(),
                'aws_profile': profile_name,
                'service_details': {}
            }
        
        # Check each requested service
        for service_name in services:
            # Process status update
            service_start_time = datetime.datetime.now()
            print(f"Checking {service_name} status in {region}...")
            if debug:
                print(f"[DEBUG:CheckReliabilityServices] Starting check for {service_name}")
            
            service_result = None
            
            # Call the appropriate check function based on service name
            if service_name.lower() == 'route53':
                service_result = await check_route53_health_checks(region, session, ctx)
            elif service_name.lower() == 'cloudwatch':
                service_result = await check_cloudwatch_alarms(region, session, ctx)
            elif service_name.lower() == 'autoscaling':
                service_result = await check_auto_scaling_groups(region, session, ctx)
            elif service_name.lower() == 'elb':
                service_result = await check_load_balancers(region, session, ctx)
            elif service_name.lower() == 'backup':
                service_result = await check_backup_vaults(region, session, ctx)
            else:
                # Log warning
                print(f"WARNING: Unknown service: {service_name}. Skipping.")
                continue
            
            # Add service result to the output
            results['service_statuses'][service_name] = service_result
            
            # Update all_configured flag
            if service_result and not service_result.get('enabled', False):
                results['all_configured'] = False
                
            # Add debug info for this service if debug is enabled
            if debug:
                service_end_time = datetime.datetime.now()
                service_duration = (service_end_time - service_start_time).total_seconds()
                
                if 'debug_info' in results and 'service_details' in results['debug_info']:
                    results['debug_info']['service_details'][service_name] = {
                        'duration_seconds': service_duration,
                        'enabled': service_result.get('enabled', False) if service_result else False,
                        'timestamp': service_end_time.isoformat(),
                        'status': 'success' if service_result else 'error'
                    }
                
                print(f"[DEBUG:CheckReliabilityServices] {service_name} check completed in {service_duration:.2f} seconds")
        
        # Generate summary based on results
        enabled_services = [name for name, status in results['service_statuses'].items() 
                          if status.get('enabled', False)]
        disabled_services = [name for name, status in results['service_statuses'].items() 
                           if not status.get('enabled', False)]
        
        summary = []
        if enabled_services:
            summary.append(f"Configured services: {', '.join(enabled_services)}")
        
        if disabled_services:
            summary.append(f"Unconfigured services: {', '.join(disabled_services)}")
            summary.append("Consider configuring these services to improve your reliability posture.")
        
        results['summary'] = " ".join(summary)
        
        # Store results in context if requested
        if store_in_context:
            context_key = f"reliability_services_{region}"
            context_storage[context_key] = results
            print(f"Stored reliability services results in context with key: {context_key}")
        
        return results
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error checking reliability services: {e}")
        return {
            'region': region,
            'services_checked': services,
            'all_configured': False,
            'error': str(e),
            'message': 'Error checking reliability services status.'
        }

@mcp.tool(name='GetTrustedAdvisorChecks')
async def get_trusted_advisor_checks_tool(
    ctx: Context,
    region: str = Field(
        'us-east-1', 
        description="AWS region to retrieve checks from (Trusted Advisor is a global service, but API calls must be made to us-east-1)"
    ),
    categories: Optional[List[str]] = Field(
        None,
        description="Optional list of categories to filter by (e.g., 'fault_tolerance', 'performance', 'service_limits')"
    ),
    risk_levels: Optional[List[str]] = Field(
        None,
        description="Optional list of risk levels to filter by (e.g., 'error', 'warning', 'ok')"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
    ),
    store_in_context: bool = Field(
        True,
        description="Whether to store results in context for access by other tools"
    )
) -> Dict:
    """Retrieve reliability-related checks from AWS Trusted Advisor.

    This tool provides access to AWS Trusted Advisor checks related to reliability,
    including fault tolerance, performance, and service limits.
    
    ## Response format
    Returns a dictionary with:
    - checks: List of Trusted Advisor checks
    - summary: Summary statistics about the checks
    - message: Status message or error information
    
    ## AWS permissions required
    - support:DescribeTrustedAdvisorChecks
    - support:DescribeTrustedAdvisorCheckResult
    
    ## Note
    This tool requires Business or Enterprise Support plan to access all Trusted Advisor checks.
    """
    try:
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Get Trusted Advisor checks
        result = await get_trusted_advisor_checks(
            region=region,
            session=session,
            ctx=ctx,
            categories=categories,
            risk_levels=risk_levels
        )
        
        # Store results in context if requested
        if store_in_context and 'checks' in result:
            context_key = "trusted_advisor_checks"
            context_storage[context_key] = result
            print(f"Stored Trusted Advisor checks in context with key: {context_key}")
        
        return result
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error getting Trusted Advisor checks: {e}")
        return {
            'error': str(e),
            'message': 'Error getting Trusted Advisor checks',
            'checks': []
        }

@mcp.tool(name='GetResilienceHubAssessments')
async def get_resilience_hub_assessments_tool(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region to retrieve assessments from"
    ),
    app_arn: Optional[str] = Field(
        None,
        description="Optional ARN of a specific application to get assessments for"
    ),
    max_results: int = Field(
        100,
        description="Maximum number of results to retrieve"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
    ),
    store_in_context: bool = Field(
        True,
        description="Whether to store results in context for access by other tools"
    )
) -> Dict:
    """Retrieve assessments from AWS Resilience Hub.

    This tool provides access to AWS Resilience Hub assessments for applications,
    including resiliency scores and recommendations.
    
    ## Response format
    Returns a dictionary with:
    - applications: List of applications in Resilience Hub (if app_arn is not provided)
    - application: Application details (if app_arn is provided)
    - assessments: List of assessments
    - message: Status message or error information
    
    ## AWS permissions required
    - resiliencehub:ListApps
    - resiliencehub:DescribeApp
    - resiliencehub:ListAppAssessments
    - resiliencehub:DescribeAppAssessment
    """
    try:
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Get Resilience Hub assessments
        result = await get_resilience_hub_assessments(
            region=region,
            session=session,
            ctx=ctx,
            app_arn=app_arn,
            max_results=max_results
        )
        
        # Store results in context if requested
        if store_in_context and ('assessments' in result or 'applications' in result):
            context_key = "resilience_hub_assessments"
            context_storage[context_key] = result
            print(f"Stored Resilience Hub assessments in context with key: {context_key}")
        
        return result
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error getting Resilience Hub assessments: {e}")
        return {
            'error': str(e),
            'message': 'Error getting Resilience Hub assessments',
            'applications': [],
            'assessments': []
        }

@mcp.tool(name='GetResourceComplianceStatus')
async def get_resource_compliance_status_tool(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region where the resource is located"
    ),
    resource_id: str = Field(
        ...,
        description="The resource identifier (e.g., i-1234567890abcdef0, my-bucket-name)"
    ),
    resource_type: str = Field(
        ...,
        description="The AWS resource type (e.g., ec2-instance, s3-bucket, rds-db-instance)"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
    )
) -> Dict:
    """Get compliance information for a specific AWS resource against reliability best practices.
    
    This tool checks the compliance status of an AWS resource against reliability best practices,
    providing details about configuration, backup, high availability, and remediation guidance.
    
    ## Response format
    Returns a dictionary with:
    - resource_id: The resource identifier
    - type: The resource type
    - compliance_status: Overall compliance status (COMPLIANT, NON_COMPLIANT, UNKNOWN, ERROR)
    - compliance_details: Detailed compliance information
    - recommendations: List of recommendations for improving reliability
    
    ## AWS permissions required
    - Read permissions for the specified resource type
    """
    try:
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        print(f"Getting compliance status for {resource_type} {resource_id}...")
        
        # Get resource compliance status
        return await get_resource_compliance_status(
            region=region,
            resource_id=resource_id,
            resource_type=resource_type,
            session=session,
            ctx=ctx
        )
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error getting compliance status: {e}")
        return {
            'resource_id': resource_id,
            'type': resource_type,
            'compliance_status': 'ERROR',
            'message': str(e)
        }

@mcp.tool(name='ExploreAwsResources')
async def explore_aws_resources(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region to explore resources in"
    ),
    services: List[str] = Field(
        ...,
        description="List of AWS services to explore (e.g., ['ec2', 's3', 'rds', 'lambda'])"
    ),
    include_summary: bool = Field(
        True,
        description="Whether to include a resource summary"
    ),
    search_tag_key: Optional[str] = Field(
        None,
        description="Optional tag key to filter resources by"
    ),
    search_tag_value: Optional[str] = Field(
        None,
        description="Optional tag value to filter resources by (used with search_tag_key)"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
    ),
    store_in_context: bool = Field(
        True,
        description="Whether to store results in context for access by other tools"
    )
) -> Dict:
    """Explore AWS resources in a specified region across multiple services.

    This tool provides a comprehensive inventory of AWS resources within the specified region,
    allowing you to understand what resources are deployed and how they are configured.
    It can be used for reliability assessment, cost analysis, or general infrastructure auditing.
    
    ## Response format
    Returns a dictionary with:
    - region: The region that was explored
    - resources: Resource details organized by service and resource type
    - summary: Resource count summary (if include_summary is True)
    - tagged_resources: Resources matching the specified tags (if search_tag_key is provided)
    
    ## AWS permissions required
    - Read permissions for each service being explored (e.g., ec2:Describe*, s3:List*, rds:Describe*)
    - resourcegroupstaggingapi:GetResources (if using tag filtering)
    """
    try:
        print("Starting resource exploration...")
        
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Validate services
        valid_services = [
            's3', 'ec2', 'rds', 'lambda', 'dynamodb', 'route53', 
            'cloudwatch', 'autoscaling', 'elb', 'elbv2', 'backup'
        ]
        
        for service in services:
            if service not in valid_services and service not in SERVICE_DESCRIPTIONS:
                print(f"WARNING: Service '{service}' may not be supported. Supported services: {', '.join(valid_services)}")
        
        # List resources for the specified services
        print(f"Exploring resources across {len(services)} services in {region}...")
        
        resources_by_service = {}
        for service in services:
            service_resources = await list_resources_by_service(region, service, session, ctx)
            if service_resources:
                resources_by_service[service] = service_resources
        
        # Generate summary if requested
        summary = None
        if include_summary:
            print("Generating resource summary...")
            summary = await resource_inventory_summary({region: resources_by_service})
        
        # Search for tagged resources if requested
        tagged_resources = None
        if search_tag_key:
            print(f"Searching for resources with tag key: {search_tag_key}")
            tagged_resources = await get_tagged_resources(
                [region], 
                search_tag_key, 
                search_tag_value, 
                session, 
                ctx
            )
        
        # Prepare response
        response = {
            'region': region,
            'services_explored': services,
            'resources': resources_by_service
        }
        
        if summary:
            response['summary'] = summary
        
        if tagged_resources:
            response['tagged_resources'] = tagged_resources
        
        # Store results in context if requested
        if store_in_context:
            context_key = f"resources_{region}"
            context_storage[context_key] = response
            print(f"Stored resource exploration results in context with key: {context_key}")
        
        print("Resource exploration complete")
        return response
        
    except Exception as e:
        # Log error
        print(f"ERROR: Error exploring AWS resources: {e}")
        return {
            'region': region,
            'services_explored': services,
            'error': str(e),
            'message': 'Error exploring AWS resources'
        }

@mcp.tool(name='AnalyzeReliabilityPosture')
async def analyze_reliability_posture(
    ctx: Context,
    regions: List[str] = Field(
        [AWS_REGION], 
        description="AWS regions to analyze (e.g., ['us-east-1', 'eu-west-1'])"
    ),
    services: Optional[List[str]] = Field(
        None, 
        description="""Optional list of AWS services to focus on.
        If not specified, all relevant reliability services will be analyzed.
        Common values include: 's3', 'ec2', 'rds', 'dynamodb', 'route53', 'cloudwatch', 'autoscaling', 'elb', 'backup'"""
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE, 
        description="Optional AWS profile to use for authentication"
    ),
    debug: bool = Field(
        False,
        description="Enable detailed debug output for each analysis phase"
    )
) -> Dict:
    """Analyze AWS reliability posture against Well-Architected Framework Reliability Pillar.
    
    This tool performs a comprehensive reliability assessment of your AWS environment by:
    1. Integrating with AWS reliability services (Trusted Advisor, Resilience Hub, etc.)
    2. Dynamically discovering resources that need reliability evaluation
    3. Analyzing reliability gaps and applying Well-Architected best practices
    4. Generating a detailed remediation plan with potential impact analysis
    
    ## Progress updates
    The tool provides progress updates during the analysis process.
    
    ## Response format
    Returns a dictionary with:
    - reliability_assessment: Detailed reliability findings and recommendations
    - remediation_plan: Actionable steps to improve reliability posture
    - resources_analyzed: Count of AWS resources analyzed
    - findings_count: Total number of reliability findings
    - debug_output: (If debug=True) Detailed output from each phase of analysis
    
    ## Required AWS permissions
    This tool requires read-only permissions to analyze the specified services.
    For specific IAM policies, refer to the AWS documentation for each service.
    """
    try:
        # Create a debug output dictionary if debug is enabled
        debug_output = {} if debug else None
        
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Define default services if none provided
        if not services:
            services = [
                's3', 'ec2', 'rds', 'dynamodb', 'route53', 
                'cloudwatch', 'autoscaling', 'elb', 'elbv2', 'backup'
            ]
        
        # Log analysis start
        print(f"Starting reliability posture analysis for regions: {', '.join(regions)}")
        
        # Phase 1: Resource Discovery
        phase1_start_time = datetime.datetime.now()
        print("Phase 1: Discovering AWS resources...")
        
        all_resources = {}
        for region in regions:
            print(f"Exploring resources in region: {region}")
            
            resources_by_service = {}
            for service in services:
                service_resources = await list_resources_by_service(region, service, session, ctx)
                if service_resources:
                    resources_by_service[service] = service_resources
            
            all_resources[region] = resources_by_service
        
        phase1_end_time = datetime.datetime.now()
        phase1_duration = (phase1_end_time - phase1_start_time).total_seconds()
        
        # Debug output for Phase 1
        if debug:
            resource_counts = {}
            for region, region_resources in all_resources.items():
                regional_count = sum(
                    len(resources) for service in region_resources.values() 
                    for resource_type, resources in service.items()
                )
                resource_counts[region] = regional_count
            
            debug_output['phase1'] = {
                'start_time': str(phase1_start_time),
                'end_time': str(phase1_end_time),
                'duration_seconds': phase1_duration,
                'resources_per_region': resource_counts,
                'total_resources': sum(resource_counts.values()),
                'services_scanned': list(set(
                    service for region_resources in all_resources.values() 
                    for service in region_resources.keys()
                ))
            }
        
        print(f"Phase 1 completed in {phase1_duration:.2f} seconds. Discovered resources in {len(all_resources)} regions.")
        
        # Phase 2: Trusted Advisor Integration
        phase2_start_time = datetime.datetime.now()
        print("Phase 2: Retrieving Trusted Advisor checks...")
        
        trusted_advisor_checks = await get_trusted_advisor_checks(
            region='us-east-1',  # Trusted Advisor is a global service
            session=session,
            ctx=ctx,
            categories=TRUSTED_ADVISOR_RELIABILITY_CATEGORIES
        )
        
        phase2_end_time = datetime.datetime.now()
        phase2_duration = (phase2_end_time - phase2_start_time).total_seconds()
        
        # Debug output for Phase 2
        if debug:
            debug_output['phase2'] = {
                'start_time': str(phase2_start_time),
                'end_time': str(phase2_end_time),
                'duration_seconds': phase2_duration,
                'checks_retrieved': len(trusted_advisor_checks.get('checks', [])),
                'status_counts': trusted_advisor_checks.get('summary', {}).get('status_counts', {})
            }
        
        print(f"Phase 2 completed in {phase2_duration:.2f} seconds. Retrieved {len(trusted_advisor_checks.get('checks', []))} Trusted Advisor checks.")
        
        # Phase 3: Resilience Hub Integration (if available)
        phase3_start_time = datetime.datetime.now()
        print("Phase 3: Retrieving Resilience Hub assessments...")
        
        resilience_hub_assessments = {}
        try:
            for region in regions:
                regional_assessments = await get_resilience_hub_assessments(
                    region=region,
                    session=session,
                    ctx=ctx
                )
                
                if 'applications' in regional_assessments and regional_assessments['applications']:
                    resilience_hub_assessments[region] = regional_assessments
        except Exception as e:
            print(f"WARNING: Error retrieving Resilience Hub assessments: {e}")
        
        phase3_end_time = datetime.datetime.now()
        phase3_duration = (phase3_end_time - phase3_start_time).total_seconds()
        
        # Debug output for Phase 3
        if debug:
            assessment_counts = {}
            for region, data in resilience_hub_assessments.items():
                assessment_counts[region] = len(data.get('assessments', []))
            
            debug_output['phase3'] = {
                'start_time': str(phase3_start_time),
                'end_time': str(phase3_end_time),
                'duration_seconds': phase3_duration,
                'assessments_per_region': assessment_counts,
                'total_assessments': sum(assessment_counts.values())
            }
        
        print(f"Phase 3 completed in {phase3_duration:.2f} seconds.")
        
        # Phase 4: Gap Analysis
        phase4_start_time = datetime.datetime.now()
        print("Phase 4: Identifying reliability gaps...")
        
        reliability_gaps = {}
        for region, resources in all_resources.items():
            regional_gaps = await identify_reliability_gaps(
                region=region,
                session=session,
                ctx=ctx,
                resources=resources,
                trusted_advisor_checks=trusted_advisor_checks,
                resilience_hub_assessments=resilience_hub_assessments.get(region)
            )
            
            reliability_gaps[region] = regional_gaps
        
        phase4_end_time = datetime.datetime.now()
        phase4_duration = (phase4_end_time - phase4_start_time).total_seconds()
        
        # Debug output for Phase 4
        if debug:
            gap_counts = {}
            for region, data in reliability_gaps.items():
                gap_counts[region] = len(data.get('gaps', []))
            
            debug_output['phase4'] = {
                'start_time': str(phase4_start_time),
                'end_time': str(phase4_end_time),
                'duration_seconds': phase4_duration,
                'gaps_per_region': gap_counts,
                'total_gaps': sum(gap_counts.values())
            }
        
        print(f"Phase 4 completed in {phase4_duration:.2f} seconds.")
        
        # Phase 5: Generate Assessment and Remediation Plan
        phase5_start_time = datetime.datetime.now()
        print("Phase 5: Generating reliability assessment and remediation plan...")
        
        # Consolidate all gaps across regions
        all_gaps = []
        for region, data in reliability_gaps.items():
            regional_gaps = data.get('gaps', [])
            for gap in regional_gaps:
                gap['region'] = region
                all_gaps.append(gap)
        
        # Group gaps by category
        gaps_by_category = {}
        for gap in all_gaps:
            category = gap.get('category', 'unknown')
            if category not in gaps_by_category:
                gaps_by_category[category] = []
            gaps_by_category[category].append(gap)
        
        # Generate reliability assessment
        reliability_assessment = {
            'overall_status': 'COMPLIANT' if not all_gaps else 'NON_COMPLIANT',
            'regions_analyzed': regions,
            'services_analyzed': services,
            'findings_count': len(all_gaps),
            'findings_by_severity': {
                'high': len([g for g in all_gaps if g.get('severity') == 'HIGH']),
                'medium': len([g for g in all_gaps if g.get('severity') == 'MEDIUM']),
                'low': len([g for g in all_gaps if g.get('severity') == 'LOW'])
            },
            'findings_by_category': {
                category: len(gaps) for category, gaps in gaps_by_category.items()
            },
            'findings': all_gaps
        }
        
        # Generate remediation plan
        remediation_plan = {
            'summary': f"Found {len(all_gaps)} reliability issues that need remediation.",
            'priority_actions': [],
            'actions_by_category': {}
        }
        
        # Add priority actions (high severity gaps)
        high_severity_gaps = [g for g in all_gaps if g.get('severity') == 'HIGH']
        for gap in high_severity_gaps:
            remediation_plan['priority_actions'].append({
                'title': gap.get('title', 'Unknown issue'),
                'description': gap.get('description', 'No description available'),
                'recommendation': gap.get('recommendation', 'No recommendation available'),
                'region': gap.get('region', 'unknown'),
                'affected_resources': gap.get('affected_resources', [])
            })
        
        # Group actions by category
        for category, gaps in gaps_by_category.items():
            remediation_plan['actions_by_category'][category] = [
                {
                    'title': gap.get('title', 'Unknown issue'),
                    'description': gap.get('description', 'No description available'),
                    'recommendation': gap.get('recommendation', 'No recommendation available'),
                    'region': gap.get('region', 'unknown'),
                    'severity': gap.get('severity', 'MEDIUM'),
                    'affected_resources': gap.get('affected_resources', [])
                }
                for gap in gaps
            ]
        
        phase5_end_time = datetime.datetime.now()
        phase5_duration = (phase5_end_time - phase5_start_time).total_seconds()
        
        # Debug output for Phase 5
        if debug:
            debug_output['phase5'] = {
                'start_time': str(phase5_start_time),
                'end_time': str(phase5_end_time),
                'duration_seconds': phase5_duration
            }
        
        print(f"Phase 5 completed in {phase5_duration:.2f} seconds.")
        
        # Calculate final metrics
        resource_count = sum(
            len(resources) for region in all_resources.values() 
            for service in region.values() 
            for resource_type, resources in service.items()
        )
        
        findings_count = len(all_gaps)
        
        total_duration = (datetime.datetime.now() - phase1_start_time).total_seconds()
        print(f"Reliability posture analysis completed in {total_duration:.2f} seconds.")
        print(f"Analyzed {resource_count} resources and found {findings_count} reliability findings.")
        
        # Prepare final response
        response = {
            "reliability_assessment": reliability_assessment,
            "remediation_plan": remediation_plan,
            "resources_analyzed": resource_count,
            "findings_count": findings_count
        }
        
        # Add debug output if requested
        if debug:
            debug_output['total_duration_seconds'] = total_duration
            response['debug_output'] = debug_output
        
        return response
    except Exception as e:
        # Log error
        print(f"ERROR: Error analyzing reliability posture: {e}")
        return {
            'error': str(e),
            'message': 'Error analyzing reliability posture',
            'resources_analyzed': 0,
            'findings_count': 0
        }

@mcp.tool(name='IdentifyReliabilityGaps')
async def identify_reliability_gaps_tool(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region to analyze"
    ),
    services: List[str] = Field(
        ['s3', 'ec2', 'rds', 'dynamodb', 'route53', 'cloudwatch', 'autoscaling', 'elb', 'backup'],
        description="List of AWS services to analyze"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
    ),
    use_trusted_advisor: bool = Field(
        True,
        description="Whether to include Trusted Advisor checks in the analysis"
    ),
    use_resilience_hub: bool = Field(
        True,
        description="Whether to include Resilience Hub assessments in the analysis"
    )
) -> Dict:
    """Identify gaps between current configuration and reliability best practices.
    
    This tool analyzes your AWS resources and identifies gaps between your current configuration
    and reliability best practices based on the AWS Well-Architected Framework.
    
    ## Response format
    Returns a dictionary with:
    - gaps: List of identified reliability gaps
    - summary: Summary statistics about the gaps
    - message: Status message or error information
    
    ## AWS permissions required
    - Read permissions for each service being analyzed
    - support:DescribeTrustedAdvisorChecks (if use_trusted_advisor is True)
    - support:DescribeTrustedAdvisorCheckResult (if use_trusted_advisor is True)
    - resiliencehub:ListApps (if use_resilience_hub is True)
    - resiliencehub:DescribeApp (if use_resilience_hub is True)
    - resiliencehub:ListAppAssessments (if use_resilience_hub is True)
    - resiliencehub:DescribeAppAssessment (if use_resilience_hub is True)
    """
    try:
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        print(f"Starting reliability gap analysis for region: {region}")
        
        # Get resources for the specified services
        resources = {}
        for service in services:
            service_resources = await list_resources_by_service(region, service, session, ctx)
            if service_resources:
                resources[service] = service_resources
        
        # Get Trusted Advisor checks if requested
        trusted_advisor_checks = None
        if use_trusted_advisor:
            print("Retrieving Trusted Advisor checks...")
            trusted_advisor_checks = await get_trusted_advisor_checks(
                region='us-east-1',  # Trusted Advisor is a global service
                session=session,
                ctx=ctx,
                categories=TRUSTED_ADVISOR_RELIABILITY_CATEGORIES
            )
        
        # Get Resilience Hub assessments if requested
        resilience_hub_assessments = None
        if use_resilience_hub:
            print("Retrieving Resilience Hub assessments...")
            resilience_hub_assessments = await get_resilience_hub_assessments(
                region=region,
                session=session,
                ctx=ctx
            )
        
        # Identify reliability gaps
        print("Identifying reliability gaps...")
        result = await identify_reliability_gaps(
            region=region,
            session=session,
            ctx=ctx,
            resources=resources,
            trusted_advisor_checks=trusted_advisor_checks,
            resilience_hub_assessments=resilience_hub_assessments
        )
        
        return result
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error identifying reliability gaps: {e}")
        return {
            'error': str(e),
            'message': 'Error identifying reliability gaps',
            'gaps': []
        }

def main():
    """Run the MCP server with CLI argument support."""
    parser = argparse.ArgumentParser(description='AWS Reliability Pillar MCP Server')
    parser.add_argument('--sse', action='store_true', help='Use SSE transport')
    parser.add_argument('--port', type=int, default=8888, help='Port to run the server on')

    args = parser.parse_args()
    
    # Initialize shared components
    asyncio.run(initialize())

    logger.info(f"Starting AWS Reliability Pillar MCP Server")
    
    # Run server with appropriate transport
    if args.sse:
        logger.info(f"Running MCP server with SSE transport on port {args.port}")
        mcp.settings.port = args.port
        mcp.run(transport='sse')
    else:
        logger.info("Running MCP server with default transport")
        mcp.run()


if __name__ == '__main__':
    main()
