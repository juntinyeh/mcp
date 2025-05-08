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

# Set up AWS region and profile from environment variables
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
AWS_PROFILE = os.environ.get('AWS_PROFILE', 'default')

# Import local modules
from util.security_services import (
    check_access_analyzer,
    check_security_hub,
    check_guard_duty,
    check_inspector,
    get_analyzer_findings_count,
    get_guardduty_findings,
    get_securityhub_findings,
    get_inspector_findings,
    get_access_analyzer_findings,
)
# These are commented out until we restore resource_utils.py functionality
# from .util.resource_utils import (
#     list_resources_by_service,
#     list_all_resources,
#     resource_inventory_summary,
#     get_tagged_resources,
# )

# Constants that might be needed
SERVICE_DESCRIPTIONS = {
    's3': 'Amazon S3',
    'ec2': 'Amazon EC2',
    'rds': 'Amazon RDS',
    'lambda': 'AWS Lambda',
    'iam': 'AWS IAM',
    'cloudfront': 'Amazon CloudFront',
    'kms': 'AWS KMS',
    'sns': 'Amazon SNS',
    'sqs': 'Amazon SQS',
    'cloudwatch': 'Amazon CloudWatch',
}

# Remove default logger and add custom configuration
logger.remove()
logger.add(sys.stderr, level=os.getenv("FASTMCP_LOG_LEVEL", "DEBUG"))

# Initialize MCP Server
mcp = FastMCP(
    "aws-security-pillar-mcp-server",
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

# Global context storage for sharing data between tool calls
context_storage = {}

async def initialize():
    """Initialize shared components on startup.
    
    This function loads and initializes the security pattern catalog and rule catalog
    that will be used throughout the server's operation. If initialization fails,
    the components will be loaded on demand when needed.
    """
    global security_pattern_catalog, rule_catalog
    
    try:
        # Import core components
        # from knowledge.security_patterns import SecurityPatternCatalog
        # from rules.rule_catalog import RuleCatalog
        
        # These components will be implemented later
        # security_pattern_catalog = SecurityPatternCatalog()
        # await security_pattern_catalog.initialize()
        
        # rule_catalog = RuleCatalog()
        # await rule_catalog.initialize()
        
        logger.info("AWS Security Pillar MCP Server initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing AWS Security Pillar MCP Server: {e}")
        # Continue without initialization - components will be loaded on demand

@mcp.tool(name='CheckSecurityServices')
async def check_security_services(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region to check for security services status"
    ),
    services: List[str] = Field(
        ['guardduty', 'inspector', 'accessanalyzer', 'securityhub'], 
        description="List of security services to check. Options: guardduty, inspector, accessanalyzer, securityhub"
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
    """Verify if selected AWS security services are enabled in the specified region and account.

    This consolidated tool checks the status of multiple AWS security services in a single call,
    providing a comprehensive overview of your security posture.
    
    ## Response format
    Returns a dictionary with:
    - region: The region that was checked
    - services_checked: List of services that were checked
    - all_enabled: Boolean indicating if all specified services are enabled
    - service_statuses: Dictionary with detailed status for each service
    - summary: Summary of security recommendations
    
    ## AWS permissions required
    - guardduty:ListDetectors, guardduty:GetDetector (if checking GuardDuty)
    - inspector2:GetStatus (if checking Inspector)
    - accessanalyzer:ListAnalyzers (if checking Access Analyzer)
    - securityhub:DescribeHub (if checking Security Hub)
    """
    try:
        # Start timestamp for measuring execution time
        start_time = datetime.datetime.now()
        
        if debug:
            print(f"[DEBUG:CheckSecurityServices] Starting security services check for region: {region}")
            print(f"[DEBUG:CheckSecurityServices] Services to check: {', '.join(services)}")
            print(f"[DEBUG:CheckSecurityServices] Using AWS profile: {aws_profile or 'default'}")
        
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Initialize results
        results = {
            'region': region,
            'services_checked': services,
            'all_enabled': True,
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
                print(f"[DEBUG:CheckSecurityServices] Starting check for {service_name}")
            
            service_result = None
            
            # Call the appropriate check function based on service name
            if service_name.lower() == 'guardduty':
                service_result = await check_guard_duty(region, session, ctx)
            elif service_name.lower() == 'inspector':
                service_result = await check_inspector(region, session, ctx)
            elif service_name.lower() == 'accessanalyzer':
                # Call the access analyzer check with additional debugging
                print(f"[DEBUG:CheckSecurityServices] Calling check_access_analyzer for region {region}")
                service_result = await check_access_analyzer(region, session, ctx)
                print(f"[DEBUG:CheckSecurityServices] check_access_analyzer returned: enabled={service_result.get('enabled', False)}")
                
                # If service_result says not enabled but analyzers are present, override the enabled flag
                if not service_result.get('enabled', False) and service_result.get('analyzers') and len(service_result.get('analyzers')) > 0:
                    print(f"[DEBUG:CheckSecurityServices] OVERRIDING: Access Analyzer has analyzers but reported as disabled. Setting enabled=True")
                    service_result['enabled'] = True
                    service_result['message'] = f"IAM Access Analyzer is enabled with {len(service_result['analyzers'])} analyzer(s)."
                    
                # Always log the analyzers we found
                analyzers = service_result.get('analyzers', [])
                print(f"[DEBUG:CheckSecurityServices] Access Analyzer check found {len(analyzers)} analyzers:")
                for idx, analyzer in enumerate(analyzers):
                    print(f"[DEBUG:CheckSecurityServices]   Analyzer {idx+1}: name={analyzer.get('name')}, status={analyzer.get('status')}")
                    
            elif service_name.lower() == 'securityhub':
                service_result = await check_security_hub(region, session, ctx)
            else:
                # Log warning
                print(f"WARNING: Unknown service: {service_name}. Skipping.")
                continue
            
            # Add service result to the output
            results['service_statuses'][service_name] = service_result
            
            # Update all_enabled flag
            if service_result and not service_result.get('enabled', False):
                results['all_enabled'] = False
                
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
                
                print(f"[DEBUG:CheckSecurityServices] {service_name} check completed in {service_duration:.2f} seconds")
        
        # Generate summary based on results
        enabled_services = [name for name, status in results['service_statuses'].items() 
                          if status.get('enabled', False)]
        disabled_services = [name for name, status in results['service_statuses'].items() 
                           if not status.get('enabled', False)]
        
        summary = []
        if enabled_services:
            summary.append(f"Enabled services: {', '.join(enabled_services)}")
        
        if disabled_services:
            summary.append(f"Disabled services: {', '.join(disabled_services)}")
            summary.append("Consider enabling these services to improve your security posture.")
        
        results['summary'] = " ".join(summary)
        
        # Store results in context if requested
        if store_in_context:
            context_key = f"security_services_{region}"
            context_storage[context_key] = results
            print(f"Stored security services results in context with key: {context_key}")
        
        return results
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error checking security services: {e}")
        return {
            'region': region,
            'services_checked': services,
            'all_enabled': False,
            'error': str(e),
            'message': 'Error checking security services status.'
        }

@mcp.tool(name='GetSecurityFindings')
async def get_security_findings(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
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
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
    ),
    check_enabled: bool = Field(
        True,
        description="Whether to check if service is enabled before retrieving findings"
    )
) -> Dict:
    """Retrieve security findings from AWS security services.

    This tool provides a consolidated interface to retrieve findings from various AWS security
    services, including GuardDuty, Security Hub, Inspector, and IAM Access Analyzer.
    
    It first checks if the specified security service is enabled in the region (using data from 
    a previous CheckSecurityServices call) and only retrieves findings if the service is enabled.
    
    ## Response format
    Returns a dictionary with:
    - service: The security service findings were retrieved from
    - enabled: Whether the service is enabled in the specified region
    - findings: List of findings from the service (if service is enabled)
    - summary: Summary statistics about the findings (if service is enabled)
    - message: Status message or error information
    
    ## AWS permissions required
    - Read permissions for the specified security service
    
    ## Note
    For optimal performance, run CheckSecurityServices with store_in_context=True 
    before using this tool. Otherwise, it will need to check if the service is enabled first.
    """
    try:
        # Normalize service name
        service_name = service.lower()
        
        # Check if service is supported
        if service_name not in ['guardduty', 'securityhub', 'inspector', 'accessanalyzer']:
            raise ValueError(f"Unsupported security service: {service}. " + 
                          "Supported services are: guardduty, securityhub, inspector, accessanalyzer")
        
        # Get context key for security services data
        context_key = f"security_services_{region}"
        service_status = None
        
        # First check if we need to verify service is enabled
        if check_enabled:
            # Check if security services data is available in context
            if context_key in context_storage:
                print(f"Using stored security services data for region: {region}")
                security_data = context_storage[context_key]
                
                # Check if the requested service is in the stored data
                service_statuses = security_data.get('service_statuses', {})
                if service_name in service_statuses:
                    service_status = service_statuses[service_name]
                    
                    # Check if service is enabled
                    if not service_status.get('enabled', False):
                        return {
                            'service': service_name,
                            'enabled': False,
                            'message': f"{service_name} is not enabled in region {region}. Please enable it before retrieving findings.",
                            'setup_instructions': service_status.get('setup_instructions', 'No setup instructions available.')
                        }
                else:
                    print(f"Service {service_name} not found in stored security services data. Will check directly.")
            else:
                print(f"No stored security services data found for region: {region}. Will check service status directly.")
        
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Prepare filter criteria based on severity
        filter_criteria = None
        if severity_filter:
            if service_name == 'guardduty':
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
            elif service_name == 'securityhub':
                filter_criteria = {
                    'SeverityLabel': [{'Comparison': 'EQUALS', 'Value': severity_filter.upper()}]
                }
            elif service_name == 'inspector':
                filter_criteria = {
                    'severities': [{'comparison': 'EQUALS', 'value': severity_filter.upper()}]
                }
        
        # Call appropriate service function based on service parameter
        if service_name == 'guardduty':
            print(f"Retrieving GuardDuty findings from {region}...")
            result = await get_guardduty_findings(region, session, ctx, max_findings, filter_criteria)
        elif service_name == 'securityhub':
            print(f"Retrieving Security Hub findings from {region}...")
            result = await get_securityhub_findings(region, session, ctx, max_findings, filter_criteria)
        elif service_name == 'inspector':
            print(f"Retrieving Inspector findings from {region}...")
            result = await get_inspector_findings(region, session, ctx, max_findings, filter_criteria)
        elif service_name == 'accessanalyzer':
            print(f"Retrieving IAM Access Analyzer findings from {region}...")
            result = await get_access_analyzer_findings(region, session, ctx)
        
        # Add service info to result
        result['service'] = service_name
        
        # If the result indicates the service isn't enabled, store this information
        if not result.get('enabled', True) and context_key in context_storage:
            security_data = context_storage[context_key]
            service_statuses = security_data.get('service_statuses', {})
            if service_name not in service_statuses:
                service_statuses[service_name] = {'enabled': False}
                print(f"Updated context with status for {service_name}: not enabled")
        
        return result
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error retrieving {service} findings: {e}")
        raise e

@mcp.tool(name='GetResourceComplianceStatus')
async def get_resource_compliance(
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
        description="The AWS resource type (e.g., ec2-instance, s3-bucket, iam-role)"
    ),
    aws_profile: Optional[str] = Field(
        AWS_PROFILE,
        description="Optional AWS profile to use (defaults to AWS_PROFILE environment variable)"
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
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        print(f"Getting compliance status for {resource_type} {resource_id}...")
        
        # This is a placeholder implementation since we don't have the actual get_resource_compliance_status function
        return {
            'resource_id': resource_id,
            'type': resource_type,
            'compliance_status': 'UNKNOWN',
            'message': 'Resource compliance checking not fully implemented yet',
            'region': region
        }
    
    except Exception as e:
        # Log error
        print(f"ERROR: Error getting compliance status: {e}")
        raise e


@mcp.tool(name='GetStoredSecurityContext')
async def get_stored_security_context(
    ctx: Context,
    region: str = Field(
        AWS_REGION, 
        description="AWS region to get stored security services data for"
    ),
    detailed: bool = Field(
        False,
        description="Whether to return the full details of the stored security services data"
    )
) -> Dict:
    """Retrieve security services data that was stored in context from a previous CheckSecurityServices call.
    
    This tool allows you to access security service status data stored by the CheckSecurityServices tool
    without making additional AWS API calls. This is useful for workflows where you need to reference 
    the security services status in subsequent steps.
    
    ## Response format
    Returns a dictionary with:
    - region: The region the data was stored for
    - available: Boolean indicating if data is available for the requested region
    - data: The stored security services data (if available and detailed=True)
    - summary: A summary of the stored data (if available)
    - timestamp: When the data was stored (if available)
    
    ## Note
    This tool requires that CheckSecurityServices was previously called with store_in_context=True
    for the requested region.
    """
    context_key = f"security_services_{region}"
    
    if context_key not in context_storage:
        print(f"No stored security services data found for region: {region}")
        return {
            'region': region,
            'available': False,
            'message': f"No security services data has been stored for region {region}. Call CheckSecurityServices with store_in_context=True first."
        }
    
    stored_data = context_storage[context_key]
    
    # Prepare response
    response = {
        'region': region,
        'available': True,
        'summary': stored_data.get('summary', 'No summary available'),
        'all_enabled': stored_data.get('all_enabled', False),
        'services_checked': stored_data.get('services_checked', [])
    }
    
    # Include full data if requested
    if detailed:
        response['data'] = stored_data
    
    print(f"Retrieved stored security services data for region: {region}")
    return response

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
        print("Starting resource exploration...")
        
        # Use the provided AWS profile or default to 'default'
        profile_name = aws_profile or 'default'
        
        # Create a session using the specified profile
        session = boto3.Session(profile_name=profile_name)
        
        # Validate services
        valid_services = [
            's3', 'ec2', 'rds', 'lambda', 'dynamodb', 'iam', 
            'cloudfront', 'kms', 'sns', 'sqs', 'cloudwatch'
        ]
        
        for service in services:
            if service not in valid_services and service not in SERVICE_DESCRIPTIONS:
                print(f"WARNING: Service '{service}' may not be supported. Supported services: {', '.join(valid_services)}")
        
        # This is a placeholder implementation since we don't have the resource_utils functions yet
        print(f"Exploring resources across {len(services)} services in {region}...")
        
        # Mock the response with placeholder data
        resources_by_service = {}
        for service in services:
            resources_by_service[service] = {
                f"{service}_resources": [
                    {"id": f"placeholder-{service}-1", "type": f"{service}_resource", "name": f"Sample {service.upper()} Resource 1"},
                    {"id": f"placeholder-{service}-2", "type": f"{service}_resource", "name": f"Sample {service.upper()} Resource 2"}
                ]
            }
        
        # Prepare response with placeholder data
        response = {
            'region': region,
            'services_explored': services,
            'resources': resources_by_service,
            'message': 'Resource exploration functionality not fully implemented yet',
            'summary': {
                'total_resources': sum(len(res_list) for svc in resources_by_service.values() 
                                    for res_type, res_list in svc.items()),
                'resources_by_service': {svc: len(resources) for svc, resources in resources_by_service.items()}
            }
        }
        
        print("Resource exploration complete")
        return response
        
    except Exception as e:
        # Log error
        print(f"ERROR: Error exploring AWS resources: {e}")
        raise e

@mcp.tool(name='AnalyzeSecurityPosture')
async def analyze_security_posture(
    ctx: Context,
    regions: List[str] = Field(
        [AWS_REGION], 
        description="AWS regions to analyze (e.g., ['us-east-1', 'eu-west-1'])"
    ),
    services: Optional[List[str]] = Field(
        None, 
        description="""Optional list of AWS services to focus on.
        If not specified, all relevant security services will be analyzed.
        Common values include: 's3', 'ec2', 'rds', 'iam', 'lambda'"""
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
        
        # Try to import necessary components with fallbacks
        try:
            from core.dynamic_scanner import DynamicScanner
            from rules.rule_generator import DynamicRuleGenerator
            from integrations.security_services import SecurityServicesIntegration
            from integrations.gap_analyzer import GapAnalyzer
            from remediation.remediation_generator import RemediationGenerator
            from reporting.report_generator import ReportGenerator
        except ImportError as e:
            print(f"WARNING: Could not import required modules: {e}")
            print("Using placeholder implementations for missing modules")
            
            # Define placeholder classes
            class DynamicScanner:
                def __init__(self, session):
                    self.session = session
                
                async def scan_environment(self, regions, services):
                    print(f"Placeholder: Scanning {len(regions)} regions for {services if services else 'all'} services")
                    return {region: {} for region in regions}
            
            class DynamicRuleGenerator:
                async def generate_rules(self, service, resources):
                    print(f"Placeholder: Generating rules for {service}")
                    return []
            
            class SecurityServicesIntegration:
                def __init__(self, session):
                    self.session = session
                
                async def gather_findings(self, regions):
                    print(f"Placeholder: Gathering findings from {len(regions)} regions")
                    return {region: {} for region in regions}
            
            class GapAnalyzer:
                async def analyze_gaps(self, findings, resources):
                    print("Placeholder: Analyzing security gaps")
                    return {region: {} for region in findings.keys()}
            
            class RemediationGenerator:
                def __init__(self, session):
                    self.session = session
                
                async def generate_remediation_plan(self, findings, with_dry_run=True):
                    print("Placeholder: Generating remediation plan")
                    return {"recommendations": [], "message": "Remediation plan generation not fully implemented"}
            
            class ReportGenerator:
                async def generate_report(self, findings):
                    print("Placeholder: Generating security assessment report")
                    return {"findings_summary": "Security assessment not fully implemented"}
        
        # Log analysis start
        print(f"Starting security posture analysis for regions: {', '.join(regions)}")
        print(f"[DEBUG] Starting security posture analysis for regions: {', '.join(regions)}")
        
        # Create session
        session_start_time = datetime.datetime.now()
        session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
        print(f"[DEBUG] Session created with profile: {aws_profile if aws_profile else 'default'}")
        
        # Phase 1: Security Services Integration
        phase1_start_time = datetime.datetime.now()
        print("Phase 1: Gathering findings from AWS security services...")
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
        print("Phase 2: Discovering AWS resources...")
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
        print("Phase 3: Performing gap analysis...")
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
        print("Phase 4: Generating and applying security rules...")
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
                
                # # Register with rule catalog - will be implemented later
                # for rule in rules:
                #     rule_catalog.register_rule(rule)
                
                # # Apply rules to resources - will be implemented later
                # service_findings = await rule_catalog.evaluate_resources(service, service_resources)
                
                # Placeholder until rule_catalog is implemented
                service_findings = []
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
        print("Phase 6: Generating security assessment report...")
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
        print("Phase 7: Creating remediation plan...")
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
        # Log error
        print(f"ERROR: Error analyzing security posture: {e}")
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
