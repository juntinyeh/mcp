"""
Report generator for security findings
"""

import logging
import json
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates security assessment reports from findings
    """
    
    async def generate_report(self, findings: Dict) -> Dict:
        """
        Generate a security assessment report
        
        Args:
            findings: Security findings by region, service, and resource
            
        Returns:
            Security assessment report
        """
        # Calculate report statistics
        stats = self._calculate_statistics(findings)
        
        # Create summary for each region
        regions_summary = {}
        for region, region_findings in findings.items():
            regions_summary[region] = self._generate_region_summary(region, region_findings)
            
        # Generate full report
        report = {
            'summary': self._generate_summary(stats),
            'regions': regions_summary,
            'statistics': stats,
            'recommendations': self._generate_general_recommendations(findings),
            'format_version': '1.0'
        }
        
        return report
        
    def _calculate_statistics(self, findings: Dict) -> Dict:
        """
        Calculate statistics from findings
        
        Args:
            findings: Security findings by region, service, and resource
            
        Returns:
            Statistics dictionary
        """
        stats = {
            'total_findings': 0,
            'findings_by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'findings_by_service': {},
            'findings_by_region': {},
            'resources_analyzed': 0,
            'services_analyzed': 0
        }
        
        # Process each region
        for region, region_findings in findings.items():
            region_count = 0
            
            # Process each service
            for service_name, service_findings in region_findings.items():
                service_count = 0
                
                # Initialize service if not present
                if service_name not in stats['findings_by_service']:
                    stats['findings_by_service'][service_name] = 0
                    
                # Process findings by resource type
                for resource_type, resource_findings in service_findings.items():
                    # Count resources analyzed
                    stats['resources_analyzed'] += len(resource_findings)
                    
                    # Count findings for this service
                    service_count += len(resource_findings)
                    
                    # Process individual findings
                    for finding in resource_findings:
                        if isinstance(finding, dict):
                            # Total count
                            stats['total_findings'] += 1
                            
                            # Count by severity
                            severity = finding.get('severity', 'medium').lower()
                            
                            # Map severity to standard levels
                            if severity in ['critical', 'high', 'medium', 'low', 'info']:
                                stats['findings_by_severity'][severity] += 1
                            elif 'critical' in severity:
                                stats['findings_by_severity']['critical'] += 1
                            elif 'high' in severity:
                                stats['findings_by_severity']['high'] += 1
                            elif 'medium' in severity:
                                stats['findings_by_severity']['medium'] += 1
                            elif 'low' in severity:
                                stats['findings_by_severity']['low'] += 1
                            else:
                                stats['findings_by_severity']['info'] += 1
                
                # Update service count
                stats['findings_by_service'][service_name] += service_count
                region_count += service_count
                
            # Update region count
            stats['findings_by_region'][region] = region_count
        
        # Count services analyzed
        stats['services_analyzed'] = len(stats['findings_by_service'])
        
        return stats
        
    def _generate_summary(self, stats: Dict) -> Dict:
        """
        Generate overall summary
        
        Args:
            stats: Statistics dictionary
            
        Returns:
            Summary dictionary
        """
        critical = stats['findings_by_severity']['critical']
        high = stats['findings_by_severity']['high']
        
        # Determine risk level
        risk_level = 'low'
        if critical > 0:
            risk_level = 'critical'
        elif high > 0:
            risk_level = 'high'
        elif stats['findings_by_severity']['medium'] > 0:
            risk_level = 'medium'
            
        return {
            'risk_level': risk_level,
            'total_findings': stats['total_findings'],
            'critical_findings': critical,
            'high_findings': high,
            'medium_findings': stats['findings_by_severity']['medium'],
            'low_findings': stats['findings_by_severity']['low'],
            'info_findings': stats['findings_by_severity']['info'],
            'regions_analyzed': len(stats['findings_by_region']),
            'services_analyzed': stats['services_analyzed'],
            'resources_analyzed': stats['resources_analyzed']
        }
        
    def _generate_region_summary(self, region: str, region_findings: Dict) -> Dict:
        """
        Generate summary for a region
        
        Args:
            region: AWS region
            region_findings: Findings for the region
            
        Returns:
            Region summary
        """
        region_summary = {
            'services': {},
            'total_findings': 0,
            'findings_by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Process each service
        for service_name, service_findings in region_findings.items():
            service_summary = {
                'resource_types': {},
                'total_findings': 0,
                'findings_by_severity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            }
            
            # Process findings by resource type
            for resource_type, resource_findings in service_findings.items():
                resource_type_summary = {
                    'total_findings': len(resource_findings),
                    'findings_by_severity': {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'info': 0
                    }
                }
                
                # Process individual findings
                for finding in resource_findings:
                    if isinstance(finding, dict):
                        # Get severity
                        severity = finding.get('severity', 'medium').lower()
                        
                        # Map severity to standard levels
                        if severity in ['critical', 'high', 'medium', 'low', 'info']:
                            severity_key = severity
                        elif 'critical' in severity:
                            severity_key = 'critical'
                        elif 'high' in severity:
                            severity_key = 'high'
                        elif 'medium' in severity:
                            severity_key = 'medium'
                        elif 'low' in severity:
                            severity_key = 'low'
                        else:
                            severity_key = 'info'
                            
                        # Update resource type severity count
                        resource_type_summary['findings_by_severity'][severity_key] += 1
                        
                        # Update service severity count
                        service_summary['findings_by_severity'][severity_key] += 1
                        
                        # Update region severity count
                        region_summary['findings_by_severity'][severity_key] += 1
                
                # Add resource type summary
                service_summary['resource_types'][resource_type] = resource_type_summary
                
                # Update service total
                service_summary['total_findings'] += resource_type_summary['total_findings']
                
            # Add service summary
            region_summary['services'][service_name] = service_summary
            
            # Update region total
            region_summary['total_findings'] += service_summary['total_findings']
                
        return region_summary
        
    def _generate_general_recommendations(self, findings: Dict) -> List[Dict]:
        """
        Generate general security recommendations
        
        Args:
            findings: Security findings by region, service, and resource
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Check for common issues and add recommendations
        
        # S3 public access issues
        s3_public_issues = self._count_issues_matching(findings, 's3', 'public')
        if s3_public_issues > 0:
            recommendations.append({
                'title': 'Block Public Access to S3 Buckets',
                'description': f"Found {s3_public_issues} potential public access issues with S3 buckets. Consider enabling S3 Block Public Access at the account level to prevent public access to all buckets.",
                'command': "aws s3control put-public-access-block --account-id {account_id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                'resources': f"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                'severity': 'high'
            })
        
        # Encryption issues
        encryption_issues = self._count_issues_matching(findings, None, 'encrypt')
        if encryption_issues > 0:
            recommendations.append({
                'title': 'Enable Default Encryption for Data Services',
                'description': f"Found {encryption_issues} potential encryption issues across services. Implement a data-at-rest encryption strategy using AWS KMS for all data services.",
                'resources': f"https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/protect-data-at-rest.html",
                'severity': 'high'
            })
        
        # Logging issues
        logging_issues = self._count_issues_matching(findings, None, 'log')
        if logging_issues > 0:
            recommendations.append({
                'title': 'Implement Centralized Logging',
                'description': f"Found {logging_issues} potential logging issues. Implement centralized logging using CloudWatch Logs and consider setting up a security information and event management (SIEM) solution.",
                'resources': f"https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/detective-controls.html",
                'severity': 'medium'
            })
        
        # CloudTrail issues
        cloudtrail_issues = self._count_issues_matching(findings, 'cloudtrail', None)
        if cloudtrail_issues > 0:
            recommendations.append({
                'title': 'Configure CloudTrail with Best Practices',
                'description': f"Found {cloudtrail_issues} potential issues with CloudTrail. Ensure CloudTrail is enabled in all regions with log file validation, multi-region logging, and encryption.",
                'command': "aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail --enable-log-file-validation --kms-key-id {kms_key_id}",
                'resources': f"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
                'severity': 'high'
            })
        
        # Security group issues
        sg_issues = self._count_issues_matching(findings, 'ec2', 'security group')
        if sg_issues > 0:
            recommendations.append({
                'title': 'Review Security Group Rules',
                'description': f"Found {sg_issues} potential issues with security groups. Review all security groups and remove overly permissive rules, especially those with public access (0.0.0.0/0).",
                'resources': f"https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/network-protection.html",
                'severity': 'high'
            })
        
        # Add general recommendations
        recommendations.append({
            'title': 'Implement AWS Security Hub',
            'description': "Enable AWS Security Hub to get a comprehensive view of your security posture across AWS accounts.",
            'command': "aws securityhub enable-security-hub",
            'resources': "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html",
            'severity': 'medium'
        })
        
        recommendations.append({
            'title': 'Review IAM Permissions',
            'description': "Regularly review IAM permissions and implement the principle of least privilege.",
            'resources': "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/security-principle-2.html",
            'severity': 'medium'
        })
        
        # Sort recommendations by severity
        recommendations = sorted(
            recommendations,
            key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['severity'], 3)
        )
        
        return recommendations
        
    def _count_issues_matching(self, findings: Dict, service_filter: Optional[str], keyword_filter: Optional[str]) -> int:
        """
        Count issues matching filters
        
        Args:
            findings: Security findings
            service_filter: Optional service filter
            keyword_filter: Optional keyword filter
            
        Returns:
            Count of matching issues
        """
        count = 0
        
        # Process each region
        for region, region_findings in findings.items():
            # Process each service
            for service_name, service_findings in region_findings.items():
                # Skip if not matching service filter
                if service_filter and service_filter != service_name:
                    continue
                    
                # Process findings by resource type
                for resource_type, resource_findings in service_findings.items():
                    for finding in resource_findings:
                        if isinstance(finding, dict):
                            # Check if finding matches keyword filter
                            matches_keyword = True
                            
                            if keyword_filter:
                                # Check in rule_id
                                rule_id = finding.get('rule_id', '')
                                description = finding.get('description', '')
                                
                                if (keyword_filter.lower() not in rule_id.lower() and 
                                    keyword_filter.lower() not in description.lower()):
                                    matches_keyword = False
                                    
                            if matches_keyword:
                                count += 1
                                
        return count
        
    def generate_security_score(self, stats: Dict) -> Dict:
        """
        Generate security score from statistics
        
        Args:
            stats: Statistics dictionary
            
        Returns:
            Security score dictionary
        """
        # Start with 100 points
        base_score = 100
        
        # Count total findings by severity
        critical = stats['findings_by_severity']['critical']
        high = stats['findings_by_severity']['high']
        medium = stats['findings_by_severity']['medium']
        low = stats['findings_by_severity']['low']
        
        # Apply penalties based on severity
        critical_penalty = min(critical * 15, 60)  # Max 60 point penalty
        high_penalty = min(high * 5, 25)  # Max 25 point penalty
        medium_penalty = min(medium * 2, 10)  # Max 10 point penalty
        low_penalty = min(low * 0.5, 5)  # Max 5 point penalty
        
        # Calculate final score
        final_score = base_score - critical_penalty - high_penalty - medium_penalty - low_penalty
        
        # Ensure score is not negative
        final_score = max(0, final_score)
        
        # Determine grade
        grade = 'F'
        if final_score >= 90:
            grade = 'A'
        elif final_score >= 80:
            grade = 'B'
        elif final_score >= 70:
            grade = 'C'
        elif final_score >= 60:
            grade = 'D'
            
        # Security status
        status = 'Critical'
        if final_score >= 90:
            status = 'Good'
        elif final_score >= 70:
            status = 'Needs Improvement'
        elif final_score >= 50:
            status = 'At Risk'
            
        return {
            'score': round(final_score, 1),
            'grade': grade,
            'status': status,
            'base_score': base_score,
            'penalties': {
                'critical': critical_penalty,
                'high': high_penalty,
                'medium': medium_penalty,
                'low': low_penalty
            }
        }
        
    def generate_markdown_report(self, report: Dict) -> str:
        """
        Generate markdown report
        
        Args:
            report: Security assessment report
            
        Returns:
            Markdown report
        """
        summary = report['summary']
        stats = report['statistics']
        recommendations = report['recommendations']
        
        # Calculate security score
        security_score = self.generate_security_score(stats)
        
        markdown = []
        
        # Title and summary
        markdown.append("# AWS Security Pillar Assessment Report\n")
        
        markdown.append("## Summary\n")
        markdown.append(f"**Security Score: {security_score['score']}/100 (Grade: {security_score['grade']}) - {security_score['status']}**\n")
        
        # Add summary table
        markdown.append("| Metric | Value |")
        markdown.append("|--------|-------|")
        markdown.append(f"| Regions Analyzed | {summary['regions_analyzed']} |")
        markdown.append(f"| Services Analyzed | {summary['services_analyzed']} |")
        markdown.append(f"| Resources Analyzed | {summary['resources_analyzed']} |")
        markdown.append(f"| Total Findings | {summary['total_findings']} |")
        markdown.append(f"| Critical Findings | {summary['critical_findings']} |")
        markdown.append(f"| High Findings | {summary['high_findings']} |")
        markdown.append(f"| Medium Findings | {summary['medium_findings']} |")
        markdown.append(f"| Low Findings | {summary['low_findings']} |")
        markdown.append("")
        
        # Risk Assessment
        markdown.append("## Risk Assessment\n")
        markdown.append(f"The overall security risk level is **{summary['risk_level'].upper()}**.\n")
        
        # Generate risk description based on level
        if summary['risk_level'] == 'critical':
            markdown.append("**Critical security issues were found that require immediate attention. These vulnerabilities could be actively exploited and pose a significant security risk.**\n")
        elif summary['risk_level'] == 'high':
            markdown.append("**High risk security issues were found. These should be addressed promptly to reduce security exposure.**\n")
        elif summary['risk_level'] == 'medium':
            markdown.append("**Medium risk security issues were found. These should be addressed as part of your regular security maintenance.**\n")
        else:
            markdown.append("**Low risk security issues were found. These represent minor configuration issues or missed best practices.**\n")
        
        # Top Recommendations
        markdown.append("## Top Recommendations\n")
        
        # Group recommendations by severity
        high_recs = [r for r in recommendations if r['severity'] == 'high']
        medium_recs = [r for r in recommendations if r['severity'] == 'medium']
        low_recs = [r for r in recommendations if r['severity'] == 'low']
        
        # Add high priority recommendations
        if high_recs:
            markdown.append("### High Priority\n")
            for rec in high_recs:
                markdown.append(f"- **{rec['title']}**: {rec['description']}")
                if 'command' in rec:
                    markdown.append(f"\n  ```\n  {rec['command']}\n  ```\n")
                if 'resources' in rec:
                    markdown.append(f"  [Learn more]({rec['resources']})\n")
        
        # Add medium priority recommendations        
        if medium_recs:
            markdown.append("### Medium Priority\n")
            for rec in medium_recs:
                markdown.append(f"- **{rec['title']}**: {rec['description']}")
                if 'command' in rec:
                    markdown.append(f"\n  ```\n  {rec['command']}\n  ```\n")
                if 'resources' in rec:
                    markdown.append(f"  [Learn more]({rec['resources']})\n")
        
        # Findings by Region
        markdown.append("## Findings by Region\n")
        
        # Sort regions by finding count
        sorted_regions = sorted(
            report['regions'].items(),
            key=lambda x: x[1]['total_findings'],
            reverse=True
        )
        
        for region, region_data in sorted_regions:
            findings_count = region_data['total_findings']
            
            if findings_count > 0:
                markdown.append(f"### {region}\n")
                markdown.append(f"Total Findings: {findings_count}")
                
                # Add severity breakdown
                severities = region_data['findings_by_severity']
                markdown.append(" (")
                severity_parts = []
                if severities['critical'] > 0:
                    severity_parts.append(f"Critical: {severities['critical']}")
                if severities['high'] > 0:
                    severity_parts.append(f"High: {severities['high']}")
                if severities['medium'] > 0:
                    severity_parts.append(f"Medium: {severities['medium']}")
                if severities['low'] > 0:
                    severity_parts.append(f"Low: {severities['low']}")
                markdown.append(", ".join(severity_parts))
                markdown.append(")\n")
                
                # Sort services by finding count
                sorted_services = sorted(
                    region_data['services'].items(),
                    key=lambda x: x[1]['total_findings'],
                    reverse=True
                )
                
                # List top services with issues
                markdown.append("Top services with issues:")
                for service_name, service_data in sorted_services[:5]:  # Top 5 services
                    markdown.append(f"- **{service_name}**: {service_data['total_findings']} findings")
                markdown.append("")
        
        return "\n".join(markdown)
