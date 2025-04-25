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

"""Utility functions for checking AWS security services and retrieving findings."""

from typing import Dict, List, Any, Optional, Union
import boto3
import json
import datetime
from loguru import logger
from mcp.server.fastmcp import Context


async def get_analyzer_findings_count(analyzer_arn: str, analyzer_client: Any, ctx: Context) -> str:
    """Get the number of findings for an IAM Access Analyzer.

    Args:
        analyzer_arn: ARN of the IAM Access Analyzer
        analyzer_client: boto3 client for Access Analyzer
        ctx: MCP context for error reporting

    Returns:
        Count of findings as string, or "Unknown" if there was an error
    """
    try:
        response = analyzer_client.list_findings(analyzerArn=analyzer_arn)
        return len(response.get('findings', []))
    except Exception as e:
        await ctx.warning(f'Error getting findings count: {e}')
        return "Unknown"


async def check_access_analyzer(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if IAM Access Analyzer is enabled in the specified region.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about IAM Access Analyzer
    """
    try:
        # Create Access Analyzer client
        analyzer_client = session.client('accessanalyzer', region_name=region)
        
        # List existing analyzers
        response = analyzer_client.list_analyzers()
        
        analyzers = response.get('analyzers', [])
        
        if not analyzers:
            # Access Analyzer is not enabled
            return {
                'enabled': False,
                'analyzers': [],
                'setup_instructions': """
                # IAM Access Analyzer Setup Instructions
                
                IAM Access Analyzer is not enabled in this region. To enable it:
                
                1. Open the IAM console: https://console.aws.amazon.com/iam/
                2. Choose Access analyzer
                3. Choose Create analyzer
                4. Enter a name for the analyzer
                5. Choose the type of analyzer (account or organization)
                6. Choose Create analyzer
                
                This is strongly recommended before proceeding with the security review.
                
                Learn more: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html
                """,
                'message': 'IAM Access Analyzer is not enabled in this region.'
            }
        
        # Access Analyzer is enabled
        return {
            'enabled': True,
            'analyzers': [
                {
                    'name': analyzer.get('name'),
                    'type': analyzer.get('type'),
                    'status': analyzer.get('status'),
                    'created_at': str(analyzer.get('createdAt')),
                    'findings_count': await get_analyzer_findings_count(analyzer.get('arn'), analyzer_client, ctx)
                }
                for analyzer in analyzers
            ],
            'message': f'IAM Access Analyzer is enabled with {len(analyzers)} analyzer(s).'
        }
    except Exception as e:
        await ctx.error(f'Error checking IAM Access Analyzer status: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking IAM Access Analyzer status.'
        }


async def check_security_hub(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if AWS Security Hub is enabled in the specified region.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about AWS Security Hub
    """
    try:
        # Create Security Hub client
        securityhub_client = session.client('securityhub', region_name=region)
        
        try:
            # Check if Security Hub is enabled
            hub_response = securityhub_client.describe_hub()
            
            # Security Hub is enabled, get enabled standards
            standards_response = securityhub_client.get_enabled_standards()
            standards = standards_response.get('StandardsSubscriptions', [])
            
            return {
                'enabled': True,
                'standards': [
                    {
                        'name': standard.get('StandardsArn', '').split('/')[-1],
                        'status': standard.get('StandardsStatus'),
                        'enabled_at': str(standard.get('StandardsSubscriptionArn', {}).get('EnabledAt', '')),
                    }
                    for standard in standards
                ],
                'message': f'Security Hub is enabled with {len(standards)} standards.'
            }
        except securityhub_client.exceptions.InvalidAccessException:
            # Security Hub is not enabled
            return {
                'enabled': False,
                'standards': [],
                'setup_instructions': """
                # AWS Security Hub Setup Instructions
                
                AWS Security Hub is not enabled in this region. To enable it:
                
                1. Open the Security Hub console: https://console.aws.amazon.com/securityhub/
                2. Choose Go to Security Hub
                3. Configure your security standards
                4. Choose Enable Security Hub
                
                This is strongly recommended for maintaining security best practices.
                
                Learn more: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-get-started.html
                """,
                'message': 'AWS Security Hub is not enabled in this region.'
            }
    except Exception as e:
        await ctx.error(f'Error checking Security Hub status: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Security Hub status.'
        }


async def check_guard_duty(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if Amazon GuardDuty is enabled in the specified region.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about Amazon GuardDuty
    """
    try:
        # Create GuardDuty client
        guardduty_client = session.client('guardduty', region_name=region)
        
        # List detectors
        detector_response = guardduty_client.list_detectors()
        detector_ids = detector_response.get('DetectorIds', [])
        
        if not detector_ids:
            # GuardDuty is not enabled
            return {
                'enabled': False,
                'detector_details': {},
                'setup_instructions': """
                # Amazon GuardDuty Setup Instructions
                
                Amazon GuardDuty is not enabled in this region. To enable it:
                
                1. Open the GuardDuty console: https://console.aws.amazon.com/guardduty/
                2. Choose Get Started
                3. Choose Enable GuardDuty
                
                This is strongly recommended for detecting threats to your AWS environment.
                
                Learn more: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html
                """,
                'message': 'Amazon GuardDuty is not enabled in this region.'
            }
            
        # GuardDuty is enabled, get detector details
        detector_id = detector_ids[0]  # Use the first detector
        detector_details = guardduty_client.get_detector(DetectorId=detector_id)
        
        return {
            'enabled': True,
            'detector_details': {
                'id': detector_id,
                'status': 'ENABLED',
                'finding_publishing_frequency': detector_details.get('FindingPublishingFrequency'),
                'data_sources': detector_details.get('DataSources'),
                'features': detector_details.get('Features', []),
            },
            'message': 'Amazon GuardDuty is enabled and active.'
        }
    except Exception as e:
        await ctx.error(f'Error checking GuardDuty status: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking GuardDuty status.'
        }


async def check_inspector(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if Amazon Inspector is enabled in the specified region.

    Args:
        region: AWS region to check
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting

    Returns:
        Dictionary with status information about Amazon Inspector
    """
    try:
        # Create Inspector client (using inspector2)
        inspector_client = session.client('inspector2', region_name=region)
        
        try:
            # Get Inspector status
            status_response = inspector_client.get_status()
            
            # Check if any scan types are enabled
            status = status_response.get('status', {})
            scan_types = ['EC2', 'ECR', 'LAMBDA']
            enabled_scans = [scan_type for scan_type in scan_types 
                             if status.get(f'{scan_type}Status') == 'ENABLED']
            
            if enabled_scans:
                return {
                    'enabled': True,
                    'scan_status': {
                        'ec2_status': status.get('EC2Status'),
                        'ecr_status': status.get('ECRStatus'),
                        'lambda_status': status.get('LAMBDAStatus'),
                    },
                    'message': f'Amazon Inspector is enabled with the following scan types: {", ".join(enabled_scans)}'
                }
            else:
                # No scan types enabled
                return {
                    'enabled': False,
                    'scan_status': {
                        'ec2_status': status.get('EC2Status'),
                        'ecr_status': status.get('ECRStatus'),
                        'lambda_status': status.get('LAMBDAStatus'),
                    },
                    'setup_instructions': """
                    # Amazon Inspector Setup Instructions
                    
                    Amazon Inspector is not fully enabled in this region. To enable it:
                    
                    1. Open the Inspector console: https://console.aws.amazon.com/inspector/
                    2. Choose Settings
                    3. Enable the scan types you need (EC2, ECR, Lambda)
                    
                    This is strongly recommended for identifying vulnerabilities in your workloads.
                    
                    Learn more: https://docs.aws.amazon.com/inspector/latest/user/enabling-disable-scanning-account.html
                    """,
                    'message': 'Amazon Inspector is installed but no scan types are enabled.'
                }
        except inspector_client.exceptions.AccessDeniedException:
            # Inspector is not enabled or permissions issue
            return {
                'enabled': False,
                'setup_instructions': """
                # Amazon Inspector Setup Instructions
                
                Amazon Inspector is not enabled in this region. To enable it:
                
                1. Open the Inspector console: https://console.aws.amazon.com/inspector/
                2. Choose Get started
                3. Choose Enable Amazon Inspector
                4. Select the scan types to enable
                
                This is strongly recommended for identifying vulnerabilities in your workloads.
                
                Learn more: https://docs.aws.amazon.com/inspector/latest/user/enabling-disable-scanning-account.html
                """,
                'message': 'Amazon Inspector is not enabled in this region.'
            }
    except Exception as e:
        await ctx.error(f'Error checking Inspector status: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Inspector status.'
        }


# New functions to get findings from security services

async def get_guardduty_findings(region: str, session: boto3.Session, ctx: Context, max_findings: int = 100, filter_criteria: Optional[Dict] = None) -> Dict:
    """Get findings from Amazon GuardDuty in the specified region.
    
    Args:
        region: AWS region to get findings from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        max_findings: Maximum number of findings to return (default: 100)
        filter_criteria: Optional filter criteria for findings
        
    Returns:
        Dictionary containing GuardDuty findings
    """
    try:
        # First check if GuardDuty is enabled
        guardduty_status = await check_guard_duty(region, session, ctx)
        if not guardduty_status.get('enabled', False):
            return {
                'enabled': False,
                'message': 'Amazon GuardDuty is not enabled in this region',
                'findings': []
            }
            
        # Get detector ID
        detector_id = guardduty_status.get('detector_details', {}).get('id')
        if not detector_id:
            await ctx.error('No GuardDuty detector ID found')
            return {
                'enabled': True,
                'error': 'No GuardDuty detector ID found',
                'findings': []
            }
            
        # Create GuardDuty client
        guardduty_client = session.client('guardduty', region_name=region)
        
        # Set up default finding criteria if none provided
        if filter_criteria is None:
            # By default, get findings from the last 30 days with high or medium severity
            filter_criteria = {
                'Criterion': {
                    'severity': {
                        'Eq': ['7', '5', '8']  # High (7), Medium (5), and Critical (8) findings
                    },
                    'updatedAt': {
                        'GreaterThanOrEqual': (datetime.datetime.now() - 
                                              datetime.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    }
                }
            }
            
        # List findings with the filter criteria
        findings_response = guardduty_client.list_findings(
            DetectorId=detector_id,
            FindingCriteria=filter_criteria,
            MaxResults=max_findings
        )
        
        finding_ids = findings_response.get('FindingIds', [])
        
        if not finding_ids:
            return {
                'enabled': True,
                'message': 'No GuardDuty findings match the filter criteria',
                'findings': []
            }
            
        # Get finding details
        findings_details = guardduty_client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )
        
        # Process findings to clean up non-serializable objects (like datetime)
        findings = []
        for finding in findings_details.get('Findings', []):
            # Convert datetime objects to strings
            finding = _clean_datetime_objects(finding)
            findings.append(finding)
        
        return {
            'enabled': True,
            'message': f'Retrieved {len(findings)} GuardDuty findings',
            'findings': findings,
            'summary': _summarize_guardduty_findings(findings)
        }
    except Exception as e:
        await ctx.error(f'Error getting GuardDuty findings: {e}')
        return {
            'enabled': True,
            'error': str(e),
            'message': 'Error getting GuardDuty findings',
            'findings': []
        }


async def get_securityhub_findings(region: str, session: boto3.Session, ctx: Context, max_findings: int = 100, filter_criteria: Optional[Dict] = None) -> Dict:
    """Get findings from AWS Security Hub in the specified region.
    
    Args:
        region: AWS region to get findings from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        max_findings: Maximum number of findings to return (default: 100)
        filter_criteria: Optional filter criteria for findings
        
    Returns:
        Dictionary containing Security Hub findings
    """
    try:
        # First check if Security Hub is enabled
        securityhub_status = await check_security_hub(region, session, ctx)
        if not securityhub_status.get('enabled', False):
            return {
                'enabled': False,
                'message': 'AWS Security Hub is not enabled in this region',
                'findings': []
            }
            
        # Create Security Hub client
        securityhub_client = session.client('securityhub', region_name=region)
        
        # Set up default finding criteria if none provided
        if filter_criteria is None:
            # By default, get active findings from the last 30 days with high severity
            filter_criteria = {
                'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}],
                'WorkflowStatus': [{'Comparison': 'EQUALS', 'Value': 'NEW'}],
                'UpdatedAt': [
                    {
                        'Start': (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                        'End': datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    }
                ],
                'SeverityLabel': [
                    {'Comparison': 'EQUALS', 'Value': 'HIGH'},
                    {'Comparison': 'EQUALS', 'Value': 'CRITICAL'}
                ]
            }
            
        # Get findings with the filter criteria
        findings_response = securityhub_client.get_findings(
            Filters=filter_criteria,
            MaxResults=max_findings
        )
        
        findings = findings_response.get('Findings', [])
        
        if not findings:
            return {
                'enabled': True,
                'message': 'No Security Hub findings match the filter criteria',
                'findings': []
            }
            
        # Process findings to clean up non-serializable objects (like datetime)
        processed_findings = []
        for finding in findings:
            # Convert datetime objects to strings
            finding = _clean_datetime_objects(finding)
            processed_findings.append(finding)
        
        return {
            'enabled': True,
            'message': f'Retrieved {len(processed_findings)} Security Hub findings',
            'findings': processed_findings,
            'summary': _summarize_securityhub_findings(processed_findings)
        }
    except Exception as e:
        await ctx.error(f'Error getting Security Hub findings: {e}')
        return {
            'enabled': True,
            'error': str(e),
            'message': 'Error getting Security Hub findings',
            'findings': []
        }


async def get_inspector_findings(region: str, session: boto3.Session, ctx: Context, max_findings: int = 100, filter_criteria: Optional[Dict] = None) -> Dict:
    """Get findings from Amazon Inspector in the specified region.
    
    Args:
        region: AWS region to get findings from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        max_findings: Maximum number of findings to return (default: 100)
        filter_criteria: Optional filter criteria for findings
        
    Returns:
        Dictionary containing Inspector findings
    """
    try:
        # First check if Inspector is enabled
        inspector_status = await check_inspector(region, session, ctx)
        if not inspector_status.get('enabled', False):
            return {
                'enabled': False,
                'message': 'Amazon Inspector is not enabled in this region',
                'findings': []
            }
            
        # Create Inspector client
        inspector_client = session.client('inspector2', region_name=region)
        
        # Set up default finding criteria if none provided
        if filter_criteria is None:
            # By default, get findings with high or critical severity
            filter_criteria = {
                'severities': [
                    {'comparison': 'EQUALS', 'value': 'HIGH'},
                    {'comparison': 'EQUALS', 'value': 'CRITICAL'}
                ],
                'findingStatus': [
                    {'comparison': 'EQUALS', 'value': 'ACTIVE'}
                ]
            }
            
        # List findings with the filter criteria
        findings_response = inspector_client.list_findings(
            filterCriteria=filter_criteria,
            maxResults=max_findings
        )
        
        findings = findings_response.get('findings', [])
        
        if not findings:
            return {
                'enabled': True,
                'message': 'No Inspector findings match the filter criteria',
                'findings': []
            }
            
        # Process findings to clean up non-serializable objects (like datetime)
        processed_findings = []
        for finding in findings:
            # Convert datetime objects to strings
            finding = _clean_datetime_objects(finding)
            processed_findings.append(finding)
        
        return {
            'enabled': True,
            'message': f'Retrieved {len(processed_findings)} Inspector findings',
            'findings': processed_findings,
            'summary': _summarize_inspector_findings(processed_findings)
        }
    except Exception as e:
        await ctx.error(f'Error getting Inspector findings: {e}')
        return {
            'enabled': True,
            'error': str(e),
            'message': 'Error getting Inspector findings',
            'findings': []
        }


async def get_access_analyzer_findings(region: str, session: boto3.Session, ctx: Context, analyzer_arn: Optional[str] = None) -> Dict:
    """Get findings from IAM Access Analyzer in the specified region.
    
    Args:
        region: AWS region to get findings from
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        analyzer_arn: Optional ARN of a specific analyzer to get findings from
        
    Returns:
        Dictionary containing IAM Access Analyzer findings
    """
    try:
        # First check if Access Analyzer is enabled
        analyzer_status = await check_access_analyzer(region, session, ctx)
        if not analyzer_status.get('enabled', False):
            return {
                'enabled': False,
                'message': 'IAM Access Analyzer is not enabled in this region',
                'findings': []
            }
            
        # Create Access Analyzer client
        analyzer_client = session.client('accessanalyzer', region_name=region)
        
        analyzers = analyzer_status.get('analyzers', [])
        if not analyzers:
            return {
                'enabled': True,
                'message': 'No IAM Access Analyzer analyzers found in this region',
                'findings': []
            }
            
        all_findings = []
        
        # If analyzer_arn is provided, only get findings for that analyzer
        if analyzer_arn:
            analyzers = [a for a in analyzers if a.get('arn') == analyzer_arn]
            
        # Get findings for each analyzer
        for analyzer in analyzers:
            analyzer_arn = analyzer.get('arn')
            if not analyzer_arn:
                continue
                
            findings_response = analyzer_client.list_findings(
                analyzerArn=analyzer_arn,
                maxResults=100
            )
            
            finding_ids = findings_response.get('findings', [])
            
            # Get details for each finding
            for finding_id in finding_ids:
                finding_details = analyzer_client.get_finding(
                    analyzerArn=analyzer_arn,
                    id=finding_id
                )
                
                # Clean up non-serializable objects
                finding_details = _clean_datetime_objects(finding_details)
                all_findings.append(finding_details)
        
        if not all_findings:
            return {
                'enabled': True,
                'message': 'No IAM Access Analyzer findings found',
                'findings': []
            }
            
        return {
            'enabled': True,
            'message': f'Retrieved {len(all_findings)} IAM Access Analyzer findings',
            'findings': all_findings,
            'summary': _summarize_access_analyzer_findings(all_findings)
        }
    except Exception as e:
        await ctx.error(f'Error getting IAM Access Analyzer findings: {e}')
        return {
            'enabled': True,
            'error': str(e),
            'message': 'Error getting IAM Access Analyzer findings',
            'findings': []
        }


# Helper functions for processing findings

def _clean_datetime_objects(obj: Any) -> Any:
    """Convert datetime objects in a nested dictionary to ISO format strings.
    
    Args:
        obj: Object that may contain datetime objects
        
    Returns:
        Object with datetime objects converted to strings
    """
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, list):
        return [_clean_datetime_objects(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: _clean_datetime_objects(v) for k, v in obj.items()}
    else:
        return obj


def _summarize_guardduty_findings(findings: List[Dict]) -> Dict:
    """Generate a summary of GuardDuty findings.
    
    Args:
        findings: List of GuardDuty finding dictionaries
        
    Returns:
        Dictionary with summary information
    """
    summary = {
        'total_count': len(findings),
        'severity_counts': {
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'type_counts': {},
        'resource_counts': {}
    }
    
    for finding in findings:
        # Count by severity
        severity = finding.get('Severity', 0)
        if severity >= 7:
            summary['severity_counts']['high'] += 1
        elif severity >= 4:
            summary['severity_counts']['medium'] += 1
        else:
            summary['severity_counts']['low'] += 1
            
        # Count by finding type
        finding_type = finding.get('Type', 'unknown')
        if finding_type in summary['type_counts']:
            summary['type_counts'][finding_type] += 1
        else:
            summary['type_counts'][finding_type] = 1
            
        # Count by resource type
        resource_type = finding.get('Resource', {}).get('ResourceType', 'unknown')
        if resource_type in summary['resource_counts']:
            summary['resource_counts'][resource_type] += 1
        else:
            summary['resource_counts'][resource_type] = 1
    
    return summary


def _summarize_securityhub_findings(findings: List[Dict]) -> Dict:
    """Generate a summary of Security Hub findings.
    
    Args:
        findings: List of Security Hub finding dictionaries
        
    Returns:
        Dictionary with summary information
    """
    summary = {
        'total_count': len(findings),
        'severity_counts': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'standard_counts': {},
        'resource_type_counts': {}
    }
    
    for finding in findings:
        # Count by severity
        severity = finding.get('Severity', {}).get('Label', 'MEDIUM').upper()
        if severity == 'CRITICAL':
            summary['severity_counts']['critical'] += 1
        elif severity == 'HIGH':
            summary['severity_counts']['high'] += 1
        elif severity == 'MEDIUM':
            summary['severity_counts']['medium'] += 1
        else:
            summary['severity_counts']['low'] += 1
            
        # Count by compliance standard
        product_name = finding.get('ProductName', 'unknown')
        if product_name in summary['standard_counts']:
            summary['standard_counts'][product_name] += 1
        else:
            summary['standard_counts'][product_name] = 1
            
        # Count by resource type
        resources = finding.get('Resources', [])
        for resource in resources:
            resource_type = resource.get('Type', 'unknown')
            if resource_type in summary['resource_type_counts']:
                summary['resource_type_counts'][resource_type] += 1
            else:
                summary['resource_type_counts'][resource_type] = 1
    
    return summary


def _summarize_inspector_findings(findings: List[Dict]) -> Dict:
    """Generate a summary of Inspector findings.
    
    Args:
        findings: List of Inspector finding dictionaries
        
    Returns:
        Dictionary with summary information
    """
    summary = {
        'total_count': len(findings),
        'severity_counts': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'type_counts': {},
        'resource_type_counts': {}
    }
    
    for finding in findings:
        # Count by severity
        severity = finding.get('severity', 'MEDIUM')
        if severity == 'CRITICAL':
            summary['severity_counts']['critical'] += 1
        elif severity == 'HIGH':
            summary['severity_counts']['high'] += 1
        elif severity == 'MEDIUM':
            summary['severity_counts']['medium'] += 1
        else:
            summary['severity_counts']['low'] += 1
            
        # Count by finding type
        finding_type = finding.get('type', 'unknown')
        if finding_type in summary['type_counts']:
            summary['type_counts'][finding_type] += 1
        else:
            summary['type_counts'][finding_type] = 1
            
        # Count by resource type
        resource_type = finding.get('resourceType', 'unknown')
        if resource_type in summary['resource_type_counts']:
            summary['resource_type_counts'][resource_type] += 1
        else:
            summary['resource_type_counts'][resource_type] = 1
    
    return summary


def _summarize_access_analyzer_findings(findings: List[Dict]) -> Dict:
    """Generate a summary of IAM Access Analyzer findings.
    
    Args:
        findings: List of IAM Access Analyzer finding dictionaries
        
    Returns:
        Dictionary with summary information
    """
    summary = {
        'total_count': len(findings),
        'resource_type_counts': {},
        'action_counts': {}
    }
    
    for finding in findings:
        # Count by resource type
        resource_type = finding.get('resourceType', 'unknown')
        if resource_type in summary['resource_type_counts']:
            summary['resource_type_counts'][resource_type] += 1
        else:
            summary['resource_type_counts'][resource_type] = 1
            
        # Count by action
        actions = finding.get('action', [])
        for action in actions:
            if action in summary['action_counts']:
                summary['action_counts'][action] += 1
            else:
                summary['action_counts'][action] = 1
    
    return summary
