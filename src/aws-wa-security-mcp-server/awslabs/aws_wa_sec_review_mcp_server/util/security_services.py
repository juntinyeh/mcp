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
        return str(len(response.get('findings', [])))
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
        print(f"[DEBUG:AccessAnalyzer] Starting Access Analyzer check for region: {region}")
        # Create Access Analyzer client
        analyzer_client = session.client('accessanalyzer', region_name=region)
        
        print(f"[DEBUG:AccessAnalyzer] Created client successfully, calling list_analyzers API")
        # List existing analyzers
        response = analyzer_client.list_analyzers()
        
        print(f"[DEBUG:AccessAnalyzer] list_analyzers response: {json.dumps(response)}")
        
        # Extract analyzers - verify the field exists to prevent KeyError
        if 'analyzers' not in response:
            print("[DEBUG:AccessAnalyzer] No 'analyzers' field in response, reporting as not enabled")
            return {
                'enabled': False,
                'analyzers': [],
                'debug_info': {'raw_response': response},
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
        
        analyzers = response.get('analyzers', [])
        
        # Log what we found for debugging
        print(f"[DEBUG:AccessAnalyzer] Found {len(analyzers)} analyzers in region {region}")
        for analyzer in analyzers:
            analyzer_name = analyzer.get('name', 'unnamed')
            analyzer_type = analyzer.get('type', 'unknown')
            analyzer_status = analyzer.get('status', 'unknown')
            analyzer_arn = analyzer.get('arn', 'unknown')
            print(f"[DEBUG:AccessAnalyzer] Analyzer: {analyzer_name}, Type: {analyzer_type}, Status: {analyzer_status}, ARN: {analyzer_arn}")
        
        if not analyzers:
            # Access Analyzer is not enabled
            print("[DEBUG:AccessAnalyzer] No analyzers found, reporting as not enabled")
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
        
        # Force to TRUE if any analyzers exist
        print(f"[DEBUG:AccessAnalyzer] Analyzers found, setting enabled=TRUE")
        
        # Check if any of the analyzers are active
        active_analyzers = [a for a in analyzers if a.get('status') == 'ACTIVE']
        print(f"[DEBUG:AccessAnalyzer] Found {len(active_analyzers)} ACTIVE analyzers")
        
        # Access Analyzer is enabled if there's at least one analyzer, even if not all are ACTIVE
        analyzer_details = []
        for analyzer in analyzers:
            analyzer_arn = analyzer.get('arn')
            if analyzer_arn:
                try:
                    findings_count = await get_analyzer_findings_count(analyzer_arn, analyzer_client, ctx)
                    print(f"[DEBUG:AccessAnalyzer] Analyzer {analyzer.get('name')} has {findings_count} findings")
                except Exception as e:
                    print(f"[DEBUG:AccessAnalyzer] Error getting findings count: {e}")
                    findings_count = "Error"
            else:
                print(f"[DEBUG:AccessAnalyzer] Missing ARN for analyzer: {analyzer.get('name')}")
                findings_count = "Unknown (No ARN)"
                
            analyzer_details.append({
                'name': analyzer.get('name'),
                'type': analyzer.get('type'),
                'status': analyzer.get('status'),
                'created_at': str(analyzer.get('createdAt')),
                'findings_count': findings_count
            })
        
        # Consider IAM Access Analyzer enabled if there's at least one analyzer, even if not all are ACTIVE
        return {
            'enabled': True,
            'analyzers': analyzer_details,
            'message': f'IAM Access Analyzer is enabled with {len(analyzers)} analyzer(s) ({len(active_analyzers)} active).'
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
    print(f"[DEBUG:SecurityHub] Starting Security Hub check for region: {region}")
    try:
        # Create Security Hub client
        securityhub_client = session.client('securityhub', region_name=region)
        
        try:
            # Check if Security Hub is enabled
            print(f"[DEBUG:SecurityHub] Calling describe_hub() to check if enabled")
            hub_response = securityhub_client.describe_hub()
            print(f"[DEBUG:SecurityHub] Security Hub is enabled. Hub ARN: {hub_response.get('HubArn', 'Unknown')}")
            
            # Security Hub is enabled, get enabled standards
            try:
                print(f"[DEBUG:SecurityHub] Getting enabled standards")
                standards_response = securityhub_client.get_enabled_standards()
                standards = standards_response.get('StandardsSubscriptions', [])
                print(f"[DEBUG:SecurityHub] Found {len(standards)} enabled standards")
                
                # Safely process standards with better error handling
                processed_standards = []
                for standard in standards:
                    try:
                        standard_name = standard.get('StandardsArn', '').split('/')[-1]
                        standard_status = standard.get('StandardsStatus', 'UNKNOWN')
                        
                        # Handle the nested structure carefully
                        enabled_at = ''
                        if 'StandardsSubscriptionArn' in standard:
                            # Sometimes EnabledAt is in the root or might not exist
                            enabled_at = str(standard.get('EnabledAt', ''))
                        
                        processed_standards.append({
                            'name': standard_name,
                            'status': standard_status,
                            'enabled_at': enabled_at
                        })
                        print(f"[DEBUG:SecurityHub] Processed standard: {standard_name} (status: {standard_status})")
                    except Exception as std_err:
                        print(f"[DEBUG:SecurityHub] Error processing a standard: {std_err}")
                        
                return {
                    'enabled': True,
                    'standards': processed_standards,
                    'message': f'Security Hub is enabled with {len(standards)} standards.',
                    'debug_info': {
                        'hub_arn': hub_response.get('HubArn', 'Unknown'),
                        'standards_count': len(standards)
                    }
                }
            except Exception as std_ex:
                print(f"[DEBUG:SecurityHub] Error getting standards: {std_ex}")
                # Security Hub is enabled but we couldn't get standards
                return {
                    'enabled': True,
                    'standards': [],
                    'message': 'Security Hub is enabled but there was an error retrieving standards.',
                    'debug_info': {
                        'hub_arn': hub_response.get('HubArn', 'Unknown'),
                        'error_getting_standards': str(std_ex)
                    }
                }
                
        except securityhub_client.exceptions.InvalidAccessException as e:
            # Security Hub is not enabled
            print(f"[DEBUG:SecurityHub] InvalidAccessException indicates Security Hub is not enabled: {e}")
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
        except securityhub_client.exceptions.ResourceNotFoundException as e:
            # Hub not found - not enabled
            print(f"[DEBUG:SecurityHub] ResourceNotFoundException indicates Security Hub is not enabled: {e}")
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
        print(f"[DEBUG:SecurityHub] ERROR: Error checking Security Hub status: {e}")
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Security Hub status.',
            'debug_info': {
                'exception': str(e),
                'exception_type': type(e).__name__
            }
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
            print(f"[DEBUG:Inspector] Calling get_status() API for region: {region}")
            try:
                # First try using get_status API
                status_response = inspector_client.get_status()
                print(f"[DEBUG:Inspector] get_status() successful, raw response: {status_response}")
                
                # If we can call get_status successfully, Inspector2 is enabled
                # Now we need to determine which scan types are enabled
                
                # The service exists and is enabled at this point, since get_status worked
                is_enabled = True
                
                # Attempt to extract status from different possible response structures
                status = {}
                
                # Check all possible paths where status might be located
                if isinstance(status_response, dict):
                    # Direct status fields in response root
                    for scan_type in ['EC2', 'ECR', 'LAMBDA', 'ec2', 'ecr', 'lambda']:
                        # Try all possible field name patterns for each scan type
                        for field_pattern in [f'{scan_type}Status', f'{scan_type.lower()}Status', 
                                             f'{scan_type}_status', f'{scan_type.lower()}_status',
                                             scan_type, scan_type.lower()]:
                            if field_pattern in status_response:
                                status[field_pattern] = status_response[field_pattern]
                    
                    # Try the 'status' nested object too
                    if 'status' in status_response and isinstance(status_response['status'], dict):
                        for key, value in status_response['status'].items():
                            # Avoid duplicates if we've already found this info
                            if key not in status:
                                status[key] = value
                                
                print(f"[DEBUG:Inspector] Extracted status fields: {status}")
                
                # Check for enabled scan types
                scan_types = ['EC2', 'ECR', 'LAMBDA']
                enabled_scans = []
                
                for scan_type in scan_types:
                    found_enabled = False
                    # Check all possible status keys for this scan type
                    for status_key in [
                        f'{scan_type}Status', 
                        f'{scan_type.lower()}Status', 
                        f'{scan_type}_status',
                        f'{scan_type.lower()}_status',
                        scan_type, 
                        scan_type.lower()
                    ]:
                        status_value = None
                        
                        # Try direct key in status dictionary
                        if status_key in status:
                            status_value = status[status_key]
                            print(f"[DEBUG:Inspector] Found status for {scan_type} via key {status_key}: {status_value}")
                        
                        # Check if the status value indicates "enabled"
                        if status_value and (
                            (isinstance(status_value, str) and status_value.upper() == 'ENABLED') or 
                            (isinstance(status_value, bool) and status_value is True)
                        ):
                            enabled_scans.append(scan_type)
                            found_enabled = True
                            print(f"[DEBUG:Inspector] {scan_type} scan type is ENABLED")
                            break
                    
                    if not found_enabled:
                        # If we haven't found an "enabled" status for this scan type, try one more approach
                        # Looking for any key that contains the scan type name and has "enabled" value
                        for status_key, status_value in status.items():
                            if (scan_type.lower() in status_key.lower() and 
                                isinstance(status_value, str) and 
                                'enable' in status_value.lower()):
                                enabled_scans.append(scan_type)
                                print(f"[DEBUG:Inspector] {scan_type} scan type is potentially enabled via fuzzy match")
                                break
                
                print(f"[DEBUG:Inspector] Final enabled scan types: {enabled_scans}")
                
                # Build the scan status dictionary
                scan_status = {}
                for scan_type in scan_types:
                    scan_found = False
                    scan_status_key = f'{scan_type.lower()}_status'
                    
                    # Look for this scan type in the status dictionary
                    for status_key, status_value in status.items():
                        if scan_type.lower() in status_key.lower():
                            scan_status[scan_status_key] = status_value
                            scan_found = True
                            break
                    
                    # If no matching key found, indicate unknown
                    if not scan_found:
                        scan_status[scan_status_key] = "UNKNOWN"
                
                # By this point, if we successfully called get_status, the service itself is enabled
                # Even if no scan types are explicitly shown as enabled
                return {
                    'enabled': is_enabled,
                    'scan_status': scan_status,
                    'message': f'Amazon Inspector is enabled with the following scan types: {", ".join(enabled_scans) if enabled_scans else "unknown"}'
                }
                
            except Exception as status_error:
                # log the error but continue with the alternative checks
                print(f"[DEBUG:Inspector] get_status() error: {status_error}")
                await ctx.warning(f"Error calling Inspector2 get_status(): {status_error}")
                
            # If get_status failed or didn't find scan types, try another approach
            # Try calling batch_get_account_status which may give different information
            try:
                print(f"[DEBUG:Inspector] Trying batch_get_account_status() as alternative")
                account_status = inspector_client.batch_get_account_status()
                print(f"[DEBUG:Inspector] batch_get_account_status returned: {account_status}")
                
                # If we get here, the service is enabled
                if 'accounts' in account_status and account_status['accounts']:
                    account_info = account_status['accounts'][0]
                    resource_status = account_info.get('resourceStatus', {})
                    
                    # Check which resources are enabled
                    ec2_enabled = resource_status.get('ec2', {}).get('status') == 'ENABLED'
                    ecr_enabled = resource_status.get('ecr', {}).get('status') == 'ENABLED'
                    lambda_enabled = resource_status.get('lambda', {}).get('status') == 'ENABLED'
                    
                    enabled_scans = []
                    if ec2_enabled:
                        enabled_scans.append('EC2')
                    if ecr_enabled:
                        enabled_scans.append('ECR')
                    if lambda_enabled:
                        enabled_scans.append('LAMBDA')
                    
                    print(f"[DEBUG:Inspector] From batch_get_account_status, enabled scans: {enabled_scans}")
                    
                    # If we successfully called batch_get_account_status, treat Inspector as enabled
                    return {
                        'enabled': True,
                        'scan_status': {
                            'ec2_status': 'ENABLED' if ec2_enabled else 'DISABLED',
                            'ecr_status': 'ENABLED' if ecr_enabled else 'DISABLED',
                            'lambda_status': 'ENABLED' if lambda_enabled else 'DISABLED',
                        },
                        'message': f'Amazon Inspector is enabled with the following scan types: {", ".join(enabled_scans) if enabled_scans else "none"}'
                    }
            except Exception as account_error:
                print(f"[DEBUG:Inspector] batch_get_account_status() error: {account_error}")
                
            # As a last resort, try listing findings
            # If this works, it means Inspector is enabled
            try:
                print("[DEBUG:Inspector] Trying list_findings() as last resort check")
                # Try listing a small number of findings just to test API access
                findings_response = inspector_client.list_findings(maxResults=1)
                print(f"[DEBUG:Inspector] list_findings successful, found {len(findings_response.get('findings', []))} findings")
                
                # If we can call list_findings, Inspector is definitely enabled
                return {
                    'enabled': True,
                    'scan_status': {
                        'ec2_status': 'UNKNOWN',
                        'ecr_status': 'UNKNOWN',
                        'lambda_status': 'UNKNOWN'
                    },
                    'message': 'Amazon Inspector is enabled, but specific scan types could not be determined.'
                }
            except Exception as findings_error:
                print(f"[DEBUG:Inspector] list_findings() error: {findings_error}")
            
            # If we get here, we've tried multiple methods but can't confirm Inspector is enabled
            print("[DEBUG:Inspector] All detection methods failed, treating as not enabled")
            return {
                'enabled': False,
                'scan_status': {
                    'ec2_status': 'UNKNOWN',
                    'ecr_status': 'UNKNOWN',
                    'lambda_status': 'UNKNOWN'
                },
                'setup_instructions': """
                # Amazon Inspector Setup Instructions
                
                Amazon Inspector may not be fully enabled in this region. To enable it:
                
                1. Open the Inspector console: https://console.aws.amazon.com/inspector/
                2. Choose Settings
                3. Enable the scan types you need (EC2, ECR, Lambda)
                
                This is strongly recommended for identifying vulnerabilities in your workloads.
                
                Learn more: https://docs.aws.amazon.com/inspector/latest/user/enabling-disable-scanning-account.html
                """,
                'message': 'Amazon Inspector status could not be determined. Multiple detection methods failed.'
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
    print(f"[DEBUG:GuardDuty] Starting findings retrieval for region: {region}")
    try:
        # First check if GuardDuty is enabled
        print(f"[DEBUG:GuardDuty] Checking if GuardDuty is enabled in {region}")
        guardduty_status = await check_guard_duty(region, session, ctx)
        if not guardduty_status.get('enabled', False):
            print(f"[DEBUG:GuardDuty] GuardDuty is not enabled in {region}")
            return {
                'enabled': False,
                'message': 'Amazon GuardDuty is not enabled in this region',
                'findings': [],
                'debug_info': 'GuardDuty is not enabled, no findings retrieved'
            }
            
        # Get detector ID
        print(f"[DEBUG:GuardDuty] GuardDuty is enabled, retrieving detector ID")
        detector_id = guardduty_status.get('detector_details', {}).get('id')
        if not detector_id:
            print(f"[DEBUG:GuardDuty] ERROR: No GuardDuty detector ID found")
            await ctx.error('No GuardDuty detector ID found')
            return {
                'enabled': True,
                'error': 'No GuardDuty detector ID found',
                'findings': [],
                'debug_info': 'GuardDuty is enabled but no detector ID was found'
            }
            
        print(f"[DEBUG:GuardDuty] Using detector ID: {detector_id}")
        
        # Create GuardDuty client
        guardduty_client = session.client('guardduty', region_name=region)
        
        # Set up default finding criteria if none provided
        if filter_criteria is None:
            print("[DEBUG:GuardDuty] No filter criteria provided, creating default criteria")
            # By default, get findings from the last 30 days with high or medium severity
            # Calculate timestamp in milliseconds (GuardDuty expects integer timestamp)
            thirty_days_ago = int((datetime.datetime.now() - datetime.timedelta(days=30)).timestamp() * 1000)
            
            filter_criteria = {
                'Criterion': {
                    'severity': {
                        'Eq': ['7', '5', '8']  # High (7), Medium (5), and Critical (8) findings
                    },
                    'updatedAt': {
                        'GreaterThanOrEqual': thirty_days_ago
                    }
                }
            }
            print(f"[DEBUG:GuardDuty] Created default filter criteria with timestamp: {thirty_days_ago} ({datetime.datetime.fromtimestamp(thirty_days_ago/1000).isoformat()})")
        else:
            print(f"[DEBUG:GuardDuty] Using provided filter criteria: {json.dumps(filter_criteria)}")
            
        # List findings with the filter criteria
        print(f"[DEBUG:GuardDuty] Calling list_findings with max results: {max_findings}")
        findings_response = guardduty_client.list_findings(
            DetectorId=detector_id,
            FindingCriteria=filter_criteria,
            MaxResults=max_findings
        )
        
        finding_ids = findings_response.get('FindingIds', [])
        print(f"[DEBUG:GuardDuty] Retrieved {len(finding_ids)} finding IDs")
        
        if not finding_ids:
            print("[DEBUG:GuardDuty] No findings match the filter criteria")
            return {
                'enabled': True,
                'message': 'No GuardDuty findings match the filter criteria',
                'findings': [],
                'debug_info': 'GuardDuty query returned no findings matching the criteria'
            }
            
        # Get finding details
        print(f"[DEBUG:GuardDuty] Retrieving details for {len(finding_ids)} findings")
        findings_details = guardduty_client.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )
        
        # Process findings to clean up non-serializable objects (like datetime)
        findings = []
        raw_findings_count = len(findings_details.get('Findings', []))
        print(f"[DEBUG:GuardDuty] Processing {raw_findings_count} findings from get_findings response")
        
        for finding in findings_details.get('Findings', []):
            # Convert datetime objects to strings
            finding = _clean_datetime_objects(finding)
            findings.append(finding)
        
        print(f"[DEBUG:GuardDuty] Successfully processed {len(findings)} findings")
        
        # Generate summary
        summary = _summarize_guardduty_findings(findings)
        print(f"[DEBUG:GuardDuty] Generated summary with {summary['total_count']} findings")
        print(f"[DEBUG:GuardDuty] Severity breakdown: High={summary['severity_counts']['high']}, Medium={summary['severity_counts']['medium']}, Low={summary['severity_counts']['low']}")
        
        return {
            'enabled': True,
            'message': f'Retrieved {len(findings)} GuardDuty findings',
            'findings': findings,
            'summary': summary,
            'debug_info': {
                'detector_id': detector_id,
                'finding_ids_retrieved': len(finding_ids),
                'findings_details_retrieved': raw_findings_count,
                'findings_processed': len(findings),
                'filter_criteria': filter_criteria
            }
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


async def check_trusted_advisor(region: str, session: boto3.Session, ctx: Context) -> Dict:
    """Check if AWS Trusted Advisor is accessible in the account.
    
    Args:
        region: AWS region to check (Trusted Advisor is a global service, but API calls must be made to us-east-1)
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        
    Returns:
        Dictionary with status information about AWS Trusted Advisor
        
    Note:
        Full Trusted Advisor functionality requires Business or Enterprise Support plan.
    """
    try:
        print(f"[DEBUG:TrustedAdvisor] Starting Trusted Advisor check")
        
        # Trusted Advisor API is only available in us-east-1
        support_client = session.client('support', region_name='us-east-1')
        
        try:
            # Try to describe Trusted Advisor checks to see if we have access
            print(f"[DEBUG:TrustedAdvisor] Calling describe_trusted_advisor_checks API")
            checks_response = support_client.describe_trusted_advisor_checks(language='en')
            
            # If we get here, we have access to Trusted Advisor
            checks = checks_response.get('checks', [])
            print(f"[DEBUG:TrustedAdvisor] Successfully retrieved {len(checks)} Trusted Advisor checks")
            
            # Count checks by category
            category_counts = {}
            for check in checks:
                category = check.get('category', 'unknown')
                if category in category_counts:
                    category_counts[category] += 1
                else:
                    category_counts[category] = 1
            
            # Count security checks specifically
            security_checks = [check for check in checks if check.get('category') == 'security']
            print(f"[DEBUG:TrustedAdvisor] Found {len(security_checks)} security-related checks")
            
            # Determine support tier based on number of checks
            # Basic support typically has 7 core checks, Business/Enterprise has 100+
            support_tier = "Basic" if len(checks) < 20 else "Business/Enterprise"
            
            return {
                'enabled': True,
                'support_tier': support_tier,
                'total_checks': len(checks),
                'security_checks': len(security_checks),
                'category_counts': category_counts,
                'message': f'AWS Trusted Advisor is accessible with {support_tier} Support ({len(checks)} checks available, {len(security_checks)} security checks).'
            }
            
        except support_client.exceptions.SubscriptionRequiredException:
            # This exception means Trusted Advisor is not available with the current support plan
            print(f"[DEBUG:TrustedAdvisor] SubscriptionRequiredException - Business or Enterprise Support required")
            return {
                'enabled': False,
                'support_tier': 'Basic',
                'setup_instructions': """
                # AWS Trusted Advisor Full Access Requirements
                
                Full access to AWS Trusted Advisor requires Business or Enterprise Support plan.
                
                With your current support plan, you have limited access to Trusted Advisor.
                To get full access to all Trusted Advisor checks:
                
                1. Open the AWS Support Center Console: https://console.aws.amazon.com/support/
                2. Choose Support Center
                3. Choose Compare or change your Support plan
                4. Upgrade to Business or Enterprise Support
                
                Learn more: https://aws.amazon.com/premiumsupport/
                """,
                'message': 'Full AWS Trusted Advisor functionality requires Business or Enterprise Support plan.'
            }
            
    except Exception as e:
        await ctx.error(f'Error checking Trusted Advisor status: {e}')
        return {
            'enabled': False,
            'error': str(e),
            'message': 'Error checking Trusted Advisor status.'
        }


async def get_trusted_advisor_findings(
    region: str, 
    session: boto3.Session, 
    ctx: Context,
    max_findings: int = 100,
    status_filter: Optional[List[str]] = None,
    category_filter: Optional[str] = None
) -> Dict:
    """Retrieve check results from AWS Trusted Advisor.
    
    Args:
        region: AWS region (Trusted Advisor is global, but API calls must be made to us-east-1)
        session: boto3 Session for AWS API calls
        ctx: MCP context for error reporting
        max_findings: Maximum number of findings to return (default: 100)
        status_filter: Optional list of statuses to filter by (e.g., ['error', 'warning'])
        category_filter: Optional category to filter by (e.g., 'security')
        
    Returns:
        Dictionary containing Trusted Advisor check results
    """
    try:
        print(f"[DEBUG:TrustedAdvisor] Starting findings retrieval")
        
        # Set default status filter if not provided
        if status_filter is None:
            status_filter = ['error', 'warning']
        
        # First check if Trusted Advisor is accessible
        ta_status = await check_trusted_advisor(region, session, ctx)
        if not ta_status.get('enabled', False):
            print(f"[DEBUG:TrustedAdvisor] Trusted Advisor is not fully accessible")
            return {
                'enabled': False,
                'message': ta_status.get('message', 'AWS Trusted Advisor is not accessible'),
                'findings': [],
                'support_tier': ta_status.get('support_tier', 'Unknown')
            }
        
        # Create Support client (Trusted Advisor API is only available in us-east-1)
        support_client = session.client('support', region_name='us-east-1')
        
        # Get all available checks
        print(f"[DEBUG:TrustedAdvisor] Getting all available checks")
        checks_response = support_client.describe_trusted_advisor_checks(language='en')
        all_checks = checks_response.get('checks', [])
        
        # Filter checks by category if specified
        filtered_checks = all_checks
        if category_filter:
            filtered_checks = [check for check in all_checks if check.get('category', '').lower() == category_filter.lower()]
            print(f"[DEBUG:TrustedAdvisor] Filtered to {len(filtered_checks)} {category_filter} checks")
        
        # Limit the number of checks to process based on max_findings
        checks_to_process = filtered_checks[:max_findings]
        
        # Get check results
        findings = []
        for check in checks_to_process:
            check_id = check.get('id')
            if not check_id:
                continue
                
            try:
                print(f"[DEBUG:TrustedAdvisor] Getting results for check: {check.get('name')} ({check_id})")
                result = support_client.describe_trusted_advisor_check_result(
                    checkId=check_id,
                    language='en'
                )
                
                # Extract the result
                check_result = result.get('result', {})
                status = check_result.get('status', '').lower()
                
                # Skip checks that don't match the status filter
                if status_filter and status not in status_filter:
                    print(f"[DEBUG:TrustedAdvisor] Skipping check with status '{status}' (not in {status_filter})")
                    continue
                
                # Format the finding
                finding = {
                    'check_id': check_id,
                    'name': check.get('name'),
                    'description': check.get('description'),
                    'category': check.get('category'),
                    'status': status,
                    'timestamp': check_result.get('timestamp'),
                    'resources_flagged': check_result.get('resourcesSummary', {}).get('resourcesFlagged', 0),
                    'resources_processed': check_result.get('resourcesSummary', {}).get('resourcesProcessed', 0),
                    'resources_suppressed': check_result.get('resourcesSummary', {}).get('resourcesSuppressed', 0),
                    'flagged_resources': []
                }
                
                # Add flagged resources
                flagged_resources = check_result.get('flaggedResources', [])
                for resource in flagged_resources:
                    # Clean up the resource data
                    resource_data = _clean_datetime_objects(resource)
                    finding['flagged_resources'].append(resource_data)
                
                findings.append(finding)
                print(f"[DEBUG:TrustedAdvisor] Added finding: {finding['name']} (status: {finding['status']}, resources: {finding['resources_flagged']})")
                
            except Exception as check_error:
                print(f"[DEBUG:TrustedAdvisor] Error getting results for check {check_id}: {check_error}")
                await ctx.warning(f"Error getting results for Trusted Advisor check {check_id}: {check_error}")
        
        # Generate summary
        summary = _summarize_trusted_advisor_findings(findings)
        
        return {
            'enabled': True,
            'message': f'Retrieved {len(findings)} Trusted Advisor findings',
            'findings': findings,
            'summary': summary,
            'support_tier': ta_status.get('support_tier', 'Unknown')
        }
        
    except Exception as e:
        await ctx.error(f'Error getting Trusted Advisor findings: {e}')
        return {
            'enabled': True,
            'error': str(e),
            'message': 'Error getting Trusted Advisor findings',
            'findings': []
        }


def _summarize_trusted_advisor_findings(findings: List[Dict]) -> Dict:
    """Generate a summary of Trusted Advisor findings.
    
    Args:
        findings: List of Trusted Advisor finding dictionaries
        
    Returns:
        Dictionary with summary information
    """
    summary = {
        'total_count': len(findings),
        'status_counts': {
            'error': 0,
            'warning': 0,
            'ok': 0,
            'not_available': 0
        },
        'category_counts': {},
        'resources_flagged': 0
    }
    
    for finding in findings:
        # Count by status
        status = finding.get('status', '').lower()
        if status in summary['status_counts']:
            summary['status_counts'][status] += 1
        else:
            summary['status_counts']['not_available'] += 1
            
        # Count by category
        category = finding.get('category', 'unknown')
        if category in summary['category_counts']:
            summary['category_counts'][category] += 1
        else:
            summary['category_counts'][category] = 1
            
        # Count total flagged resources
        summary['resources_flagged'] += finding.get('resources_flagged', 0)
    
    return summary
