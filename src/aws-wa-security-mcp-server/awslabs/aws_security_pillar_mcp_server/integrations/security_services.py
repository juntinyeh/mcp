"""
Integration with AWS security services
"""

import boto3
import logging
import asyncio
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

class SecurityServicesIntegration:
    """
    Integrates with AWS security services to gather findings
    """
    
    def __init__(self, session=None):
        """Initialize with optional boto3 session"""
        self.session = session or boto3.Session()
        
    async def gather_findings(self, regions: List[str]) -> Dict:
        """
        Gather findings from all available AWS security services
        
        Args:
            regions: List of AWS regions to gather findings from
            
        Returns:
            Dictionary of findings by region, service, and type
        """
        findings = {}
        
        # Discover and validate available security services
        security_services = await self._get_available_security_services()
        
        # Gather findings for each region
        for region in regions:
            findings[region] = {}
            
            # Gather findings concurrently for efficiency
            tasks = []
            for service_name, methods in security_services.items():
                task = asyncio.create_task(
                    self._gather_service_findings(service_name, methods, region)
                )
                tasks.append((service_name, task))
                
            # Wait for all tasks to complete
            for service_name, task in tasks:
                try:
                    service_findings = await task
                    if service_findings:
                        findings[region][service_name] = service_findings
                except Exception as e:
                    logger.error(f"Error gathering findings for {service_name} in {region}: {e}")
                    
        return findings
        
    async def _get_available_security_services(self) -> Dict[str, List[str]]:
        """
        Identify available AWS security services
        
        Returns:
            Dictionary mapping service names to their finding retrieval methods
        """
        # Potential security services and their methods to get findings
        security_services = {
            'securityhub': ['get_findings'],
            'guardduty': ['list_findings', 'get_findings'],
            'accessanalyzer': ['list_findings'],
            'config': ['get_compliance_details_by_resource'],
            'inspector': ['list_findings'],
            'macie': ['list_findings'],
            'detective': ['search_graph'],
            'cloudtrail': ['lookup_events'],
            'iam': ['get_account_authorization_details'],
            'trustedadvisor': ['describe_trusted_advisor_checks', 'describe_trusted_advisor_check_result']
        }
        
        # Filter to available services
        available_services = {}
        all_services = self.session.get_available_services()
        
        for service_name, methods in security_services.items():
            if service_name in all_services:
                # Additional validation: check if all methods are available
                client = None
                try:
                    client = self.session.client(service_name, region_name='us-east-1')
                    
                    # Check which methods are available
                    available_methods = []
                    for method_name in methods:
                        if hasattr(client, method_name) and callable(getattr(client, method_name)):
                            available_methods.append(method_name)
                            
                    if available_methods:
                        available_services[service_name] = available_methods
                        
                except Exception as e:
                    logger.debug(f"Service {service_name} not available: {e}")
                    
        return available_services
        
    async def _gather_service_findings(self, service_name: str, methods: List[str], region: str) -> Dict:
        """
        Gather findings from a specific security service
        
        Args:
            service_name: AWS security service name
            methods: List of methods to use for gathering findings
            region: AWS region
            
        Returns:
            Dictionary of findings
        """
        service_findings = {}
        
        try:
            # Create regional client
            client = self.session.client(service_name, region_name=region)
            
            # Service-specific handling
            if service_name == 'securityhub':
                service_findings = await self._gather_security_hub_findings(client)
            elif service_name == 'guardduty':
                service_findings = await self._gather_guardduty_findings(client, methods)
            elif service_name == 'accessanalyzer':
                service_findings = await self._gather_access_analyzer_findings(client)
            elif service_name == 'config':
                service_findings = await self._gather_config_findings(client)
            elif service_name == 'inspector':
                service_findings = await self._gather_inspector_findings(client)
            else:
                # Generic handling for other services
                service_findings = await self._gather_generic_findings(client, service_name, methods)
                
        except Exception as e:
            logger.error(f"Error gathering {service_name} findings in {region}: {e}")
            
        return service_findings
        
    async def _gather_security_hub_findings(self, client) -> Dict:
        """Gather findings from Security Hub"""
        findings = {}
        
        try:
            # Get Security Hub findings
            response = client.get_findings(
                Filters={
                    'WorkflowStatus': [
                        {'Value': 'NEW', 'Comparison': 'EQUALS'},
                        {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
                    ],
                    'RecordState': [
                        {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
                    ]
                },
                MaxResults=100
            )
            
            if 'Findings' in response and response['Findings']:
                findings['all_findings'] = response['Findings']
                
                # Group findings by source
                findings_by_source = {}
                for finding in response['Findings']:
                    source = finding.get('ProductName', 'unknown')
                    if source not in findings_by_source:
                        findings_by_source[source] = []
                    findings_by_source[source].append(finding)
                    
                findings['by_source'] = findings_by_source
                
                # Group by severity
                findings_by_severity = {}
                for finding in response['Findings']:
                    severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
                    if severity not in findings_by_severity:
                        findings_by_severity[severity] = []
                    findings_by_severity[severity].append(finding)
                    
                findings['by_severity'] = findings_by_severity
                
        except Exception as e:
            logger.error(f"Error gathering Security Hub findings: {e}")
            
        return findings
        
    async def _gather_guardduty_findings(self, client, methods) -> Dict:
        """Gather findings from GuardDuty"""
        findings = {}
        
        try:
            # List detectors
            list_detectors_response = client.list_detectors()
            detector_ids = list_detectors_response.get('DetectorIds', [])
            
            if detector_ids:
                detector_id = detector_ids[0]  # Use first detector
                
                # List findings
                list_findings_response = client.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'service.archived': {
                                'Eq': ['false']
                            }
                        }
                    },
                    MaxResults=50
                )
                
                finding_ids = list_findings_response.get('FindingIds', [])
                
                if finding_ids:
                    # Get finding details
                    get_findings_response = client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )
                    
                    if 'Findings' in get_findings_response:
                        findings['all_findings'] = get_findings_response['Findings']
                        
                        # Group findings by type
                        findings_by_type = {}
                        for finding in get_findings_response['Findings']:
                            finding_type = finding.get('Type', 'unknown')
                            if finding_type not in findings_by_type:
                                findings_by_type[finding_type] = []
                            findings_by_type[finding_type].append(finding)
                            
                        findings['by_type'] = findings_by_type
                        
                        # Group by severity
                        findings_by_severity = {}
                        for finding in get_findings_response['Findings']:
                            severity = finding.get('Severity', 0)
                            severity_label = 'LOW'
                            if severity >= 7.0:
                                severity_label = 'HIGH'
                            elif severity >= 4.0:
                                severity_label = 'MEDIUM'
                                
                            if severity_label not in findings_by_severity:
                                findings_by_severity[severity_label] = []
                            findings_by_severity[severity_label].append(finding)
                            
                        findings['by_severity'] = findings_by_severity
                        
        except Exception as e:
            logger.error(f"Error gathering GuardDuty findings: {e}")
            
        return findings
        
    async def _gather_access_analyzer_findings(self, client) -> Dict:
        """Gather findings from IAM Access Analyzer"""
        findings = {}
        
        try:
            # List analyzers
            list_analyzers_response = client.list_analyzers()
            analyzers = list_analyzers_response.get('analyzers', [])
            
            findings_by_analyzer = {}
            all_findings = []
            
            for analyzer in analyzers:
                analyzer_arn = analyzer.get('arn')
                
                if analyzer_arn:
                    # List findings for this analyzer
                    list_findings_response = client.list_findings(
                        analyzerArn=analyzer_arn,
                        filter={
                            'status': {
                                'eq': ['ACTIVE']
                            }
                        },
                        maxResults=100
                    )
                    
                    analyzer_findings = list_findings_response.get('findings', [])
                    findings_by_analyzer[analyzer.get('name', 'unknown')] = analyzer_findings
                    all_findings.extend(analyzer_findings)
                    
            if all_findings:
                findings['all_findings'] = all_findings
                findings['by_analyzer'] = findings_by_analyzer
                
                # Group by resource type
                findings_by_resource = {}
                for finding in all_findings:
                    resource_type = finding.get('resourceType', 'unknown')
                    if resource_type not in findings_by_resource:
                        findings_by_resource[resource_type] = []
                    findings_by_resource[resource_type].append(finding)
                    
                findings['by_resource_type'] = findings_by_resource
                
        except Exception as e:
            logger.error(f"Error gathering Access Analyzer findings: {e}")
            
        return findings
        
    async def _gather_config_findings(self, client) -> Dict:
        """Gather findings from AWS Config"""
        findings = {}
        
        try:
            # Get compliance summary
            compliance_response = client.describe_compliance_by_config_rule()
            
            if 'ComplianceByConfigRules' in compliance_response:
                findings['compliance_summary'] = compliance_response['ComplianceByConfigRules']
                
                # Get non-compliant resources for each rule
                non_compliant_rules = [
                    rule for rule in compliance_response['ComplianceByConfigRules']
                    if rule.get('Compliance', {}).get('ComplianceType') == 'NON_COMPLIANT'
                ]
                
                findings_by_rule = {}
                all_findings = []
                
                for rule in non_compliant_rules:
                    rule_name = rule.get('ConfigRuleName')
                    
                    if rule_name:
                        # Get non-compliant resources
                        resources_response = client.get_compliance_details_by_config_rule(
                            ConfigRuleName=rule_name,
                            ComplianceTypes=['NON_COMPLIANT'],
                            Limit=100
                        )
                        
                        rule_findings = resources_response.get('EvaluationResults', [])
                        findings_by_rule[rule_name] = rule_findings
                        all_findings.extend(rule_findings)
                        
                if all_findings:
                    findings['all_findings'] = all_findings
                    findings['by_rule'] = findings_by_rule
                    
                    # Group by resource type
                    findings_by_resource = {}
                    for finding in all_findings:
                        resource_type = finding.get('EvaluationResultIdentifier', {}).get(
                            'EvaluationResultQualifier', {}).get('ResourceType', 'unknown')
                        if resource_type not in findings_by_resource:
                            findings_by_resource[resource_type] = []
                        findings_by_resource[resource_type].append(finding)
                        
                    findings['by_resource_type'] = findings_by_resource
                    
        except Exception as e:
            logger.error(f"Error gathering AWS Config findings: {e}")
            
        return findings
        
    async def _gather_inspector_findings(self, client) -> Dict:
        """Gather findings from Amazon Inspector"""
        findings = {}
        
        try:
            # List findings
            list_findings_response = client.list_findings(
                findingArnList=[],
                filter={
                    'severities': ['HIGH', 'CRITICAL', 'MEDIUM']
                },
                maxResults=100
            )
            
            if 'findingArns' in list_findings_response:
                finding_arns = list_findings_response['findingArns']
                
                if finding_arns:
                    # Get finding details
                    describe_findings_response = client.describe_findings(
                        findingArns=finding_arns
                    )
                    
                    if 'findings' in describe_findings_response:
                        findings['all_findings'] = describe_findings_response['findings']
                        
                        # Group findings by type
                        findings_by_type = {}
                        for finding in describe_findings_response['findings']:
                            finding_type = finding.get('title', 'unknown')
                            if finding_type not in findings_by_type:
                                findings_by_type[finding_type] = []
                            findings_by_type[finding_type].append(finding)
                            
                        findings['by_type'] = findings_by_type
                        
                        # Group by severity
                        findings_by_severity = {}
                        for finding in describe_findings_response['findings']:
                            severity = finding.get('severity', 'UNKNOWN')
                            if severity not in findings_by_severity:
                                findings_by_severity[severity] = []
                            findings_by_severity[severity].append(finding)
                            
                        findings['by_severity'] = findings_by_severity
                        
        except Exception as e:
            logger.error(f"Error gathering Inspector findings: {e}")
            
        return findings
        
    async def _gather_generic_findings(self, client, service_name: str, methods: List[str]) -> Dict:
        """
        Generic method for gathering findings from other security services
        
        Args:
            client: AWS service client
            service_name: Service name
            methods: List of methods to try
            
        Returns:
            Dictionary of findings
        """
        findings = {}
        
        for method_name in methods:
            try:
                # Try to call method
                method = getattr(client, method_name)
                response = method()
                
                # Extract findings based on common response patterns
                if 'findings' in response:
                    findings[method_name] = response['findings']
                elif 'Findings' in response:
                    findings[method_name] = response['Findings']
                elif 'items' in response:
                    findings[method_name] = response['items']
                elif 'Items' in response:
                    findings[method_name] = response['Items']
                else:
                    # Store full response
                    findings[method_name] = response
                    
            except Exception as e:
                logger.debug(f"Error calling {method_name} for {service_name}: {e}")
                
        return findings
