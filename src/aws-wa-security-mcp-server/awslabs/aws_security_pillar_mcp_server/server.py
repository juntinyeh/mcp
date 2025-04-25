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

"""AWS Security Pillar MCP Server implementation."""

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

# Import local modules
from awslabs.aws_security_pillar_mcp_server.consts import (
    DEFAULT_REGIONS,
    INSTRUCTIONS,
    SERVICE_DESCRIPTIONS,
)
from awslabs.aws_security_pillar_mcp_server.util.security_services import (
    check_access_analyzer,
    check_security_hub,
    check_guard_duty,
    check_inspector,
    get_analyzer_findings_count,
)
from awslabs.aws_security_pillar_mcp_server.util.resource_utils import (
    list_resources_by_service,
    list_all_resources,
    resource_inventory_summary,
    get_tagged_resources,
)

# Remove default logger and add custom configuration
logger.remove()
logger.add(sys.stderr, level=os.getenv("FASTMCP_LOG_LEVEL", "WARNING"))

# Initialize MCP Server
mcp = FastMCP(
    "awslabs.aws-security-pillar-mcp-server",
    instructions=INSTRUCTIONS,
    dependencies=[
        'boto3', 
        'requests', 
        'beautifulsoup4',
        'pydantic',
        'loguru',
    ],
)

# Global shared components
security_pattern_catalog = None
rule_catalog = None

async def initialize():
    """Initialize shared components on startup.
    
    This function loads and initializes the security pattern catalog and rule catalog
    that will be used throughout the server's operation. If initialization fails,
    the components will be loaded on demand when needed.
    """
    global security_pattern_catalog, rule_catalog
    
    try:
        # Import core components
        from awslabs.aws_security_pillar_mcp_server.knowledge.security_patterns import SecurityPatternCatalog
        from awslabs.aws_security_pillar_mcp_server.rules.rule_catalog import RuleCatalog
        
        # Initialize security pattern catalog
        security_pattern_catalog = SecurityPatternCatalog()
        await security_pattern_catalog.initialize()
        
        # Initialize rule catalog
        rule_catalog = RuleCatalog()
        await rule_catalog.initialize()
        
        logger.info("AWS Security Pillar MCP Server initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing AWS Security Pillar MCP Server: {e}")
        # Continue without initialization - components will be loaded on demand

@mcp.tool(name='CheckAccessAnalyzerStatus')
async def check_access_analyzer_status(
    ctx: Context,
    region: str = Field(
        ..., 
        description="AWS region to check for IAM Access Analyzer status"
    ),
    account_id: Optional[str] = Field(
        None, 
        description="Optional AWS account ID (defaults to caller's account)"
    )
) -> Dict:
    """Verify if IAM Access Analyzer is enabled in the specified region and account.

    IAM Access Analyzer is a security tool that helps identify unintended access
    to your AWS resources. This tool checks if it's enabled and provides setup
    guidance if needed.
    
    ## Response format
    Returns a dictionary with:
    - enabled: Boolean indicating if Access Analyzer is enabled
    - analyzers: List of configured analyzers if enabled
    - setup_instructions: Instructions for enabling if not enabled
    - message: Summary message of the current state
    
    ## AWS permissions required
    - accessanalyzer:ListAnalyzers
    - accessanalyzer:ListFindings (if analyzers exist)
    """
    # Get AWS profile from environment or use default
    profile_name = ctx.env.get('AWS_PROFILE', 'default')
    
    # Create a session using the specified profile
    session = boto3.Session(profile_name=profile_name)
    
    return await check_access_analyzer(region, session, ctx)


@mcp.tool(name='CheckSecurityHubStatus')
async def check_security_hub_status(
    ctx: Context,
    region: str = Field(
        ..., 
        description="AWS region to check for Security Hub status"
    ),
    account_id: Optional[str] = Field(
        None, 
        description="Optional AWS account ID (defaults to caller's account)"
    )
) -> Dict:
    """Verify if AWS Security Hub is enabled in the specified region and account.

    Security Hub is a service that provides a comprehensive view of your security
    posture across your AWS accounts. It aggregates, organizes, and prioritizes
    your security alerts from multiple AWS services and partner products.
    
    ## Response format
    Returns a dictionary with:
    - enabled: Boolean indicating if Security Hub is enabled
    - standards: List of enabled security standards if Security Hub is enabled
    - setup_instructions: Instructions for enabling if not enabled
    - message: Summary message of the current state
    
    ## AWS permissions required
    - securityhub:DescribeHub
    - securityhub:GetEnabledStandards
    """
    # Get AWS profile from environment or use default
    profile_name = ctx.env.get('AWS_PROFILE', 'default')
    
    # Create a session using the specified profile
    session = boto3.Session(profile_name=profile_name)
    
    return await check_security_hub(region, session, ctx)


@mcp.tool(name='CheckGuardDutyStatus')
async def check_guard_duty_status(
    ctx: Context,
    region: str = Field(
        ..., 
        description="AWS region to check for GuardDuty status"
    ),
    account_id: Optional[str] = Field(
        None, 
        description="Optional AWS account ID (defaults to caller's account)"
    )
) -> Dict:
    """Verify if Amazon GuardDuty is enabled in the specified region and account.

    Amazon GuardDuty is a threat detection service that continuously monitors for
    malicious activity and unauthorized behavior to protect your AWS accounts and workloads.
    
    ## Response format
    Returns a dictionary with:
    - enabled: Boolean indicating if GuardDuty is enabled
    - detector_details: Details about the GuardDuty detector if enabled
    - setup_instructions: Instructions for enabling if not enabled
    - message: Summary message of the current state
    
    ## AWS permissions required
    - guardduty:ListDetectors
    - guardduty:GetDetector
    """
    # Get AWS profile from environment or use default
    profile_name = ctx.env.get('AWS_PROFILE', 'default')
    
    # Create a session using the specified profile
    session = boto3.Session(profile_name=profile_name)
    
    return await check_guard_duty(region, session, ctx)


@mcp.tool(name='CheckInspectorStatus')
async def check_inspector_status(
    ctx: Context,
    region: str = Field(
        ..., 
        description="AWS region to check for Amazon Inspector status"
    ),
    account_id: Optional[str] = Field(
        None, 
        description="Optional AWS account ID (defaults to caller's account)"
    )
) -> Dict:
    """Verify if Amazon Inspector is enabled in the specified region and account.

    Amazon Inspector is an automated security assessment service that helps improve
    the security and compliance of applications deployed on AWS. It automatically
    assesses applications for exposure, vulnerabilities, and deviations from best practices.
    
    ## Response format
    Returns a dictionary with:
    - enabled: Boolean indicating if Inspector is enabled
    - scan_status: Status of different scan types if Inspector is enabled
    - setup_instructions: Instructions for enabling if not enabled
    - message: Summary message of the current state
    
    ## AWS permissions required
    - inspector2:GetStatus
    """
    # Get AWS profile from environment or use default
    profile_name = ctx.env.get('AWS_PROFILE', 'default')
    
    # Create a session using the specified profile
    session = boto3.Session(profile_name=profile_name)
    
    return await check_inspector(region, session, ctx)


@mcp.tool(name='GetSecurityFindings')
async def get_security_findings(
    ctx: Context,
    region: str = Field(
        ..., 
        description="AWS region to retrieve findings from"
    ),
    service: str = Field(
        ...,
        description="Security service to retrieve findings from ('guardduty', 'securityhub', 'inspector', 'accessanalyzer')"
    ),
    max_findings: int = Field(
        100,
        description="Maximum number of findings to retrieve"
    ),
    severity_filter: Optional[str] = Field(
        None,
        description="Optional severity filter (e.g., 'HIGH', 'CRITICAL')"
    ),
    aws_profile: Optional[str] = Field(
        None,
        description="Optional AWS profile to use (defaults to the profile in context)"
    )
) -> Dict:
    """Retrieve security findings from AWS security services.

    This tool provides a consolidated interface to retrieve findings from various AWS security
    services, including GuardDuty, Security Hub, Inspector, and IAM Access Analyzer.
    
    ## Response format
    Returns a dictionary with:
    - service: The security service findings were retrieved from
    - enabled: Whether the service is enabled in the specified region
    - findings: List of findings from the service
    - summary: Summary statistics about the findings
    
    ## AWS permissions required
    - Read permissions for the specified security service
    """
    try:
        # Get AWS profile from parameters, environment, or use default
        profile_name = aws_profile or ctx.env.get('AWS_PROFILE', 'default')
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Prepare filter criteria based on severity
        filter_criteria = None
        if severity_filter:
            if service.lower() == 'guardduty':
                # GuardDuty uses numeric severity levels
                severity_mapping = {
                    'LOW': ['1', '2', '3'],
                    'MEDIUM': ['4', '5', '6'],
                    'HIGH': ['7', '8'],
                    'CRITICAL': ['8'],
                }
                if severity_filter.upper() in severity_mapping:
                    filter_criteria = {
                        'Criterion': {
                            'severity': {
                                'Eq': severity_mapping[severity_filter.upper()]
                            }
                        }
                    }
            elif service.lower() == 'securityhub':
                filter_criteria = {
                    'SeverityLabel': [{'Comparison': 'EQUALS', 'Value': severity_filter.upper()}]
                }
            elif service.lower() == 'inspector':
                filter_criteria = {
                    'severities': [{'comparison': 'EQUALS', 'value': severity_filter.upper()}]
                }
        
        # Call appropriate service function based on service parameter
        if service.lower() == 'guardduty':
            await ctx.progress(message=f"Retrieving GuardDuty findings from {region}...")
            result = await get_guardduty_findings(region, session, ctx, max_findings, filter_criteria)
        elif service.lower() == 'securityhub':
            await ctx.progress(message=f"Retrieving Security Hub findings from {region}...")
            result = await get_securityhub_findings(region, session, ctx, max_findings, filter_criteria)
        elif service.lower() == 'inspector':
            await ctx.progress(message=f"Retrieving Inspector findings from {region}...")
            result = await get_inspector_findings(region, session, ctx, max_findings, filter_criteria)
        elif service.lower() == 'accessanalyzer':
            await ctx.progress(message=f"Retrieving IAM Access Analyzer findings from {region}...")
            result = await get_access_analyzer_findings(region, session, ctx)
        else:
            raise ValueError(f"Unsupported security service: {service}. " + 
                            "Supported services are: guardduty, securityhub, inspector, accessanalyzer")
        
        # Add service info to result
        result['service'] = service.lower()
        return result
    
    except Exception as e:
        await ctx.error(f"Error retrieving {service} findings: {e}")
        raise e


@mcp.tool(name='GetResourceComplianceStatus')
async def get_resource_compliance(
    ctx: Context,
    region: str = Field(
        ..., 
        description="AWS region where the resource is located"
    ),
    resource_id: str = Field(
        ...,
        description="The resource identifier (e.g., i-1234567890abcdef0, my-bucket-name)"
    ),
    resource_type: str = Field(
        ...,
        description="The AWS resource type (e.g., ec2-instance, s3-bucket, iam-role)"
    ),
    aws_profile: Optional[str] = Field(
        None,
        description="Optional AWS profile to use (defaults to the profile in context)"
    )
) -> Dict:
    """Get compliance information for a specific AWS resource.

    This tool checks the compliance status of an AWS resource against deployed AWS Config rules.
    It provides details about rule compliance, configuration history, and remediation guidance.
    
    ## Response format
    Returns a dictionary with:
    - resource_id: The resource identifier
    - type: The resource type
    - compliance_status: Overall compliance status (COMPLIANT, NON_COMPLIANT, UNKNOWN, ERROR)
    - compliance_by_rule: Compliance details for each applicable rule
    - configuration: Resource configuration details
    
    ## AWS permissions required
    - config:GetResourceConfigHistory
    - config:GetComplianceDetailsByResource
    """
    try:
        # Get AWS profile from parameters, environment, or use default
        profile_name = aws_profile or ctx.env.get('AWS_PROFILE', 'default')
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        await ctx.progress(message=f"Getting compliance status for {resource_type} {resource_id}...")
        result = await get_resource_compliance_status(region, resource_id, resource_type, session, ctx)
        
        return result
    
    except Exception as e:
        await ctx.error(f"Error getting compliance status: {e}")
        raise e


@mcp.tool(name='ExploreAwsResources')
async def explore_aws_resources(
    ctx: Context,
    region: str = Field(
        ..., 
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
        None,
        description="Optional AWS profile to use (defaults to the profile in context)"
    )
) -> Dict:
    """Explore AWS resources in a specified region across multiple services.

    This tool provides a comprehensive inventory of AWS resources within the specified region,
    allowing you to understand what resources are deployed and how they are configured.
    It can be used for security assessment, cost analysis, or general infrastructure auditing.
    
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
        await ctx.progress(message="Starting resource exploration...")
        
        # Get AWS profile from parameters, environment, or use default
        profile_name = aws_profile or ctx.env.get('AWS_PROFILE', 'default')
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Validate services
        valid_services = [
            's3', 'ec2', 'rds', 'lambda', 'dynamodb', 'iam', 
            'cloudfront', 'kms', 'sns', 'sqs', 'cloudwatch'
        ]
        
        for service in services:
            if service not in valid_services and service not in SERVICE_DESCRIPTIONS:
                await ctx.warning(f"Service '{service}' may not be supported. Supported services: {', '.join(valid_services)}")
        
        # Explore resources
        await ctx.progress(message=f"Exploring resources across {len(services)} services in {region}...")
        
        # We'll use a single region for this tool
        regions = [region]
        resources = await list_all_resources(regions, services, session, ctx, parallel=False)
        
        # Get resource summary if requested
        summary = None
        if include_summary:
            await ctx.progress(message="Generating resource summary...")
            summary = await resource_inventory_summary(resources)
        
        # Get tagged resources if requested
        tagged_resources = None
        if search_tag_key:
            await ctx.progress(message=f"Searching for resources with tag '{search_tag_key}'...")
            tagged_resources = await get_tagged_resources(
                regions, 
                tag_key=search_tag_key,
                tag_value=search_tag_value,
                session=session, 
                ctx=ctx
            )
        
        # Prepare response
        response = {
            'region': region,
            'services_explored': services,
            'resources': resources.get(region, {}),
        }
        
        if summary:
            response['summary'] = summary
            
        if tagged_resources:
            response['tagged_resources'] = tagged_resources.get(region, [])
        
        await ctx.progress(message="Resource exploration complete")
        return response
        
    except Exception as e:
        await ctx.error(f"Error exploring AWS resources: {e}")
        raise e

@mcp.tool(name='AnalyzeSecurityPosture')
async def analyze_security_posture(
    ctx: Context,
    regions: List[str] = Field(
        ..., 
        description="AWS regions to analyze (e.g., ['us-east-1', 'eu-west-1'])"
    ),
    services: Optional[List[str]] = Field(
        None, 
        description="""Optional list of AWS services to focus on.
        If not specified, all relevant security services will be analyzed.
        Common values include: 's3', 'ec2', 'rds', 'iam', 'lambda'"""
    ),
    aws_profile: Optional[str] = Field(
        None, 
        description="Optional AWS profile to use for authentication"
    ),
    debug: bool = Field(
        False,
        description="Enable detailed debug output for each analysis phase"
    )
) -> Dict:
    """Analyze AWS security posture against Well-Architected Framework Security Pillar.
    
    This tool performs a comprehensive security assessment of your AWS environment by:
    1. Integrating with AWS security services (Security Hub, GuardDuty, etc.)
    2. Dynamically discovering resources that need security evaluation
    3. Analyzing security gaps and applying Well-Architected best practices
    4. Generating a detailed remediation plan with potential impact analysis
    
    ## Progress updates
    The tool provides progress updates during the analysis process.
    
    ## Response format
    Returns a dictionary with:
    - security_assessment: Detailed security findings and recommendations
    - remediation_plan: Actionable steps to improve security posture
    - resources_analyzed: Count of AWS resources analyzed
    - findings_count: Total number of security findings
    - debug_output: (If debug=True) Detailed output from each phase of analysis
    
    ## Required AWS permissions
    This tool requires read-only permissions to analyze the specified services.
    For specific IAM policies, refer to the AWS documentation for each service.
    """
    try:
        # Create a debug output dictionary if debug is enabled
        debug_output = {} if debug else None
        
        # Import necessary components
        from awslabs.aws_security_pillar_mcp_server.core.dynamic_scanner import DynamicScanner
        from awslabs.aws_security_pillar_mcp_server.rules.rule_generator import DynamicRuleGenerator
        from awslabs.aws_security_pillar_mcp_server.integrations.security_services import SecurityServicesIntegration
        from awslabs.aws_security_pillar_mcp_server.integrations.gap_analyzer import GapAnalyzer
        from awslabs.aws_security_pillar_mcp_server.remediation.remediation_generator import RemediationGenerator
        from awslabs.aws_security_pillar_mcp_server.reporting.report_generator import ReportGenerator
        
        # Log analysis start
        await ctx.progress(message=f"Starting security posture analysis for regions: {', '.join(regions)}")
        print(f"[DEBUG] Starting security posture analysis for regions: {', '.join(regions)}")
        
        # Create session
        session_start_time = datetime.datetime.now()
        session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
        print(f"[DEBUG] Session created with profile: {aws_profile if aws_profile else 'default'}")
        
        # Phase 1: Security Services Integration
        phase1_start_time = datetime.datetime.now()
        await ctx.progress(message="Phase 1: Gathering findings from AWS security services...")
        print(f"[DEBUG] Phase 1: Security Services Integration started at {phase1_start_time}")
        
        security_services = SecurityServicesIntegration(session)
        native_findings = await security_services.gather_findings(regions)
        
        phase1_end_time = datetime.datetime.now()
        phase1_duration = (phase1_end_time - phase1_start_time).total_seconds()
        
        # Debug output for Phase 1
        if debug:
            findings_counts = {}
            for region in regions:
                regional_count = sum(len(findings) for findings in native_findings.get(region, {}).values())
                findings_counts[region] = regional_count
            
            debug_output['phase1'] = {
                'start_time': str(phase1_start_time),
                'end_time': str(phase1_end_time),
                'duration_seconds': phase1_duration,
                'findings_per_region': findings_counts,
                'total_findings': sum(findings_counts.values())
            }
        
        print(f"[DEBUG] Phase 1 completed in {phase1_duration:.2f} seconds. Found findings in {len(native_findings)} regions.")
        
        # Phase 2: Dynamic Resource Discovery
        phase2_start_time = datetime.datetime.now()
        await ctx.progress(message="Phase 2: Discovering AWS resources...")
        print(f"[DEBUG] Phase 2: Dynamic Resource Discovery started at {phase2_start_time}")
        
        scanner = DynamicScanner(session)
        discovered_resources = await scanner.scan_environment(regions, services)
        
        phase2_end_time = datetime.datetime.now()
        phase2_duration = (phase2_end_time - phase2_start_time).total_seconds()
        
        # Debug output for Phase 2
        if debug:
            resource_counts = {}
            for region, region_resources in discovered_resources.items():
                regional_count = sum(
                    len(resources) for service in region_resources.values() 
                    for resource_type, resources in service.items()
                )
                resource_counts[region] = regional_count
            
            debug_output['phase2'] = {
                'start_time': str(phase2_start_time),
                'end_time': str(phase2_end_time),
                'duration_seconds': phase2_duration,
                'resources_per_region': resource_counts,
                'total_resources': sum(resource_counts.values()),
                'services_scanned': list(set(
                    service for region_resources in discovered_resources.values() 
                    for service in region_resources.keys()
                ))
            }
        
        print(f"[DEBUG] Phase 2 completed in {phase2_duration:.2f} seconds. Discovered resources in {len(discovered_resources)} regions.")
        
        # Phase 3: Gap Analysis
        phase3_start_time = datetime.datetime.now()
        await ctx.progress(message="Phase 3: Performing gap analysis...")
        print(f"[DEBUG] Phase 3: Gap Analysis started at {phase3_start_time}")
        
        gap_analyzer = GapAnalyzer()
        gaps = await gap_analyzer.analyze_gaps(native_findings, discovered_resources)
        
        phase3_end_time = datetime.datetime.now()
        phase3_duration = (phase3_end_time - phase3_start_time).total_seconds()
        
        # Debug output for Phase 3
        if debug:
            gap_counts = {}
            for region, region_gaps in gaps.items():
                regional_count = sum(len(resources) for resources in region_gaps.values())
                gap_counts[region] = regional_count
            
            debug_output['phase3'] = {
                'start_time': str(phase3_start_time),
                'end_time': str(phase3_end_time),
                'duration_seconds': phase3_duration,
                'gaps_per_region': gap_counts,
                'total_gaps': sum(gap_counts.values()),
            }
        
        print(f"[DEBUG] Phase 3 completed in {phase3_duration:.2f} seconds. Identified gaps in {len(gaps)} regions.")
        
        # Phase 4: Dynamic Rule Generation and Application
        phase4_start_time = datetime.datetime.now()
        await ctx.progress(message="Phase 4: Generating and applying security rules...")
        print(f"[DEBUG] Phase 4: Rule Generation and Application started at {phase4_start_time}")
        
        rule_generator = DynamicRuleGenerator()
        scanner_findings = {}
        rule_count = 0
        
        # Generate and apply rules for gaps
        for region, region_gaps in gaps.items():
            scanner_findings[region] = {}
            for service, service_resources in region_gaps.items():
                # Generate rules for this service
                rules = await rule_generator.generate_rules(service, service_resources)
                rule_count += len(rules)
                
                # Register with rule catalog
                for rule in rules:
                    rule_catalog.register_rule(rule)
                
                # Apply rules to resources
                service_findings = await rule_catalog.evaluate_resources(service, service_resources)
                scanner_findings[region][service] = service_findings
        
        phase4_end_time = datetime.datetime.now()
        phase4_duration = (phase4_end_time - phase4_start_time).total_seconds()
        
        # Debug output for Phase 4
        if debug:
            finding_counts = {}
            for region, region_findings in scanner_findings.items():
                regional_count = sum(len(findings) for findings in region_findings.values())
                finding_counts[region] = regional_count
            
            debug_output['phase4'] = {
                'start_time': str(phase4_start_time),
                'end_time': str(phase4_end_time),
                'duration_seconds': phase4_duration,
                'rules_generated': rule_count,
                'findings_per_region': finding_counts,
                'total_findings': sum(finding_counts.values()),
            }
        
        print(f"[DEBUG] Phase 4 completed in {phase4_duration:.2f} seconds. Generated {rule_count} rules.")
        
        # Phase 5: Consolidate Findings
        phase5_start_time = datetime.datetime.now()
        print(f"[DEBUG] Phase 5: Consolidating Findings started at {phase5_start_time}")
        
        # Consolidate findings
        all_findings = {}
        for region in regions:
            all_findings[region] = {}
            # Add native findings
            for service, findings in native_findings.get(region, {}).items():
                all_findings[region][service] = findings
            # Add scanner findings
            for service, findings in scanner_findings.get(region, {}).items():
                if service in all_findings[region]:
                    all_findings[region][service].extend(findings)
                else:
                    all_findings[region][service] = findings
        
        phase5_end_time = datetime.datetime.now()
        phase5_duration = (phase5_end_time - phase5_start_time).total_seconds()
        print(f"[DEBUG] Phase 5 completed in {phase5_duration:.2f} seconds.")
        
        # Phase 6: Report Generation
        phase6_start_time = datetime.datetime.now()
        await ctx.progress(message="Phase 6: Generating security assessment report...")
        print(f"[DEBUG] Phase 6: Report Generation started at {phase6_start_time}")
        
        report_generator = ReportGenerator()
        report = await report_generator.generate_report(all_findings)
        
        phase6_end_time = datetime.datetime.now()
        phase6_duration = (phase6_end_time - phase6_start_time).total_seconds()
        
        if debug:
            debug_output['phase6'] = {
                'start_time': str(phase6_start_time),
                'end_time': str(phase6_end_time),
                'duration_seconds': phase6_duration,
            }
        
        print(f"[DEBUG] Phase 6 completed in {phase6_duration:.2f} seconds.")
        
        # Phase 7: Remediation Plan Generation
        phase7_start_time = datetime.datetime.now()
        await ctx.progress(message="Phase 7: Creating remediation plan...")
        print(f"[DEBUG] Phase 7: Remediation Plan Generation started at {phase7_start_time}")
        
        remediation_generator = RemediationGenerator(session)
        remediation_plan = await remediation_generator.generate_remediation_plan(
            all_findings, with_dry_run=True
        )
        
        phase7_end_time = datetime.datetime.now()
        phase7_duration = (phase7_end_time - phase7_start_time).total_seconds()
        
        if debug:
            debug_output['phase7'] = {
                'start_time': str(phase7_start_time),
                'end_time': str(phase7_end_time),
                'duration_seconds': phase7_duration,
            }
        
        print(f"[DEBUG] Phase 7 completed in {phase7_duration:.2f} seconds.")
        
        # Calculate final metrics
        resource_count = sum(
            len(resources) for region in discovered_resources.values() 
            for service in region.values() 
            for resource_type, resources in service.items()
        )
        
        findings_count = sum(
            len(findings) for region in all_findings.values() 
            for service in region.values() 
            for findings in service.values()
        )
        
        total_duration = (datetime.datetime.now() - session_start_time).total_seconds()
        print(f"[DEBUG] Security posture analysis completed in {total_duration:.2f} seconds.")
        print(f"[DEBUG] Analyzed {resource_count} resources and found {findings_count} security findings.")
        
        # Prepare final response
        response = {
            "security_assessment": report,
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
        await ctx.error(f"Error analyzing security posture: {e}")
        raise e

def main():
    """Run the MCP server with CLI argument support."""
    parser = argparse.ArgumentParser(description='AWS Security Pillar MCP Server')
    parser.add_argument('--sse', action='store_true', help='Use SSE transport')
    parser.add_argument('--port', type=int, default=8888, help='Port to run the server on')

    args = parser.parse_args()
    
    # Initialize shared components
    asyncio.run(initialize())

    logger.info(f"Starting AWS Security Pillar MCP Server")
    
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
