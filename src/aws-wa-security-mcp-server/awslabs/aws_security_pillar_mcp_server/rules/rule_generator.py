"""
Dynamic rule generator for AWS security rules
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

class DynamicRuleGenerator:
    """
    Generates security rules dynamically based on service properties
    """
    
    def __init__(self):
        """Initialize the rule generator"""
        # Default security patterns common across services
        self.security_patterns = {
            'public_access': {
                'keywords': ['public', 'everyone', 'allusers', 'anonymous', '0.0.0.0/0', '::/0'],
                'property_patterns': ['public.*access', '.*public', 'globally.*', 'anonymous.*'],
                'severity': 'high',
                'description': 'Public access security issue',
                'remediation_template': 'Configure {property} to restrict public access'
            },
            'encryption': {
                'keywords': ['encrypt', 'kms', 'ssl', 'tls', 'https'],
                'property_patterns': ['encrypt.*', 'ssl.*', 'tls.*', '.*encrypted', '.*encryption'],
                'severity': 'high',
                'description': 'Encryption security issue',
                'remediation_template': 'Enable encryption for {property}'
            },
            'logging': {
                'keywords': ['log', 'audit', 'trail'],
                'property_patterns': ['logging.*', '.*logging', 'audit.*', '.*trail'],
                'severity': 'medium',
                'description': 'Logging security issue',
                'remediation_template': 'Enable logging for {property}'
            },
            'authentication': {
                'keywords': ['auth', 'iam', 'role', 'permission', 'policy', 'cred'],
                'property_patterns': ['auth.*', 'iam.*', '.*role', '.*policy', '.*permission'],
                'severity': 'high',
                'description': 'Authentication security issue',
                'remediation_template': 'Configure proper authentication for {property}'
            },
            'network_security': {
                'keywords': ['vpc', 'subnet', 'security group', 'nacl', 'firewall'],
                'property_patterns': ['vpc.*', '.*vpc', 'private.*', 'security.*group', 'firewall.*'],
                'severity': 'high',
                'description': 'Network security issue',
                'remediation_template': 'Review network security settings for {property}'
            }
        }
        
    async def generate_rules(self, service_name: str, service_resources: Dict) -> List[Dict]:
        """
        Generate security rules for a specific AWS service
        
        Args:
            service_name: AWS service name
            service_resources: Resources discovered for the service
            
        Returns:
            List of generated security rules
        """
        rules = []
        
        # Extract properties from resources
        properties = self._extract_properties(service_resources)
        
        # Generate rules based on properties
        for prop, prop_info in properties.items():
            for pattern_name, pattern in self.security_patterns.items():
                if self._matches_security_pattern(prop, pattern):
                    rule = self._create_rule(service_name, prop, prop_info['type'], pattern_name, pattern)
                    rules.append(rule)
        
        # Add service-specific rules
        service_rules = self._get_service_specific_rules(service_name)
        rules.extend(service_rules)
        
        return rules
        
    def _extract_properties(self, service_resources: Dict) -> Dict:
        """
        Extract properties from service resources
        
        Args:
            service_resources: Resources discovered for a service
            
        Returns:
            Dictionary of property names and their types
        """
        properties = {}
        
        # Process each resource type
        for resource_type, resources in service_resources.items():
            if not isinstance(resources, list):
                continue
                
            for resource in resources:
                if not isinstance(resource, dict):
                    continue
                
                # Extract properties from the resource
                for prop, value in resource.items():
                    if prop not in properties:
                        properties[prop] = {
                            'type': type(value).__name__,
                            'resource_types': set([resource_type])
                        }
                    else:
                        properties[prop]['resource_types'].add(resource_type)
        
        return properties
        
    def _matches_security_pattern(self, prop: str, pattern: Dict) -> bool:
        """
        Check if a property matches a security pattern
        
        Args:
            prop: Property name
            pattern: Security pattern definition
            
        Returns:
            True if property matches pattern, False otherwise
        """
        # Convert property name to lowercase for case-insensitive matching
        prop_lower = prop.lower()
        
        # Check if property contains any pattern keywords
        for keyword in pattern['keywords']:
            if keyword.lower() in prop_lower:
                return True
                
        # Check if property matches any regex patterns
        for pattern_regex in pattern['property_patterns']:
            if re.search(pattern_regex, prop_lower):
                return True
                
        return False
        
    def _create_rule(
        self, service_name: str, property_name: str, 
        property_type: str, pattern_name: str, pattern: Dict
    ) -> Dict:
        """
        Create a security rule for a property and pattern
        
        Args:
            service_name: AWS service name
            property_name: Property name
            property_type: Property type
            pattern_name: Security pattern name
            pattern: Security pattern definition
            
        Returns:
            Security rule definition
        """
        # Generate a unique rule ID
        rule_id = f"{service_name}_{pattern_name}_{property_name}"
        
        # Generate remediation command template
        remediation_command = self._generate_remediation_command(
            service_name, property_name, pattern_name, pattern
        )
        
        # Create rule object
        rule = {
            'id': rule_id,
            'service_name': service_name,
            'property_name': property_name,
            'pattern_name': pattern_name,
            'severity': pattern['severity'],
            'description': f"{pattern['description']} found in {property_name}",
            'remediation': pattern['remediation_template'].format(property=property_name),
            'remediation_command': remediation_command,
            # Function to check if a resource violates this rule
            'check': self._generate_check_function(property_name, pattern_name, pattern)
        }
        
        return rule
        
    def _generate_check_function(self, property_name: str, pattern_name: str, pattern: Dict) -> Dict:
        """
        Generate a check function for a rule
        
        Args:
            property_name: Property name
            pattern_name: Pattern name
            pattern: Security pattern definition
            
        Returns:
            Check function definition
        """
        # Different checks based on pattern type
        if pattern_name == 'public_access':
            return {
                'type': 'property_value',
                'property': property_name,
                'operator': 'contains',
                'values': ['public', 'everyone', '*', '0.0.0.0/0', '::/0']
            }
        elif pattern_name == 'encryption':
            return {
                'type': 'property_value',
                'property': property_name,
                'operator': 'equals',
                'values': [False, 'false', 'False', 'DISABLED', 'disabled', None]
            }
        elif pattern_name == 'logging':
            return {
                'type': 'property_value',
                'property': property_name,
                'operator': 'equals',
                'values': [False, 'false', 'False', 'DISABLED', 'disabled', None]
            }
        else:
            # Default check
            return {
                'type': 'property_exists',
                'property': property_name
            }
        
    def _generate_remediation_command(
        self, service_name: str, property_name: str, 
        pattern_name: str, pattern: Dict
    ) -> str:
        """
        Generate AWS CLI remediation command
        
        Args:
            service_name: AWS service name
            property_name: Property name
            pattern_name: Security pattern name
            pattern: Security pattern definition
            
        Returns:
            AWS CLI command for remediation
        """
        # Transform service name for CLI commands
        cli_service = service_name.replace('_', '-')
        
        # Generate update action
        update_action = f"update-{service_name.replace('_', '-')}"
        if service_name.startswith('aws'):
            update_action = service_name.split('.')[-1]
            
        # Common properties for commands
        resource_identifier = "{resource-id}"
        
        # Pattern-specific commands
        if pattern_name == 'public_access':
            if 's3' in service_name:
                return f"aws s3api put-public-access-block --bucket {resource_identifier} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            elif 'ec2' in service_name and 'security-group' in property_name.lower():
                return f"aws ec2 revoke-security-group-ingress --group-id {resource_identifier} --cidr 0.0.0.0/0"
            else:
                return f"aws {cli_service} {update_action} --{property_name.replace('Public', 'public')}=false --{resource_identifier}"
                
        elif pattern_name == 'encryption':
            if 's3' in service_name:
                return f"aws s3api put-bucket-encryption --bucket {resource_identifier} --server-side-encryption-configuration 'Rules=[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]'"
            elif 'rds' in service_name:
                return f"aws rds modify-db-instance --db-instance-identifier {resource_identifier} --storage-encrypted"
            elif 'dynamodb' in service_name:
                return f"aws dynamodb update-table --table-name {resource_identifier} --sse-specification Enabled=true,SSEType=KMS"
            else:
                return f"aws {cli_service} {update_action} --{property_name.replace('Encryption', 'encryption')}=true --{resource_identifier}"
                
        elif pattern_name == 'logging':
            if 's3' in service_name:
                return f"aws s3api put-bucket-logging --bucket {resource_identifier} --bucket-logging-status 'LoggingEnabled={{\"TargetBucket\":\"{resource_identifier}-logs\",\"TargetPrefix\":\"{resource_identifier}/\"}}'"
            elif 'cloudtrail' in service_name:
                return f"aws cloudtrail update-trail --name {resource_identifier} --enable-log-file-validation"
            else:
                return f"aws {cli_service} {update_action} --{property_name.replace('Logging', 'logging')}=true --{resource_identifier}"
        
        # Default command
        return f"aws {cli_service} {update_action} --{property_name}=true --{resource_identifier}"
        
    def _get_service_specific_rules(self, service_name: str) -> List[Dict]:
        """
        Get service-specific rules
        
        Args:
            service_name: AWS service name
            
        Returns:
            List of service-specific rules
        """
        rules = []
        
        # S3 specific rules
        if service_name == 's3':
            rules.append({
                'id': 's3_versioning',
                'service_name': 's3',
                'property_name': 'Versioning',
                'pattern_name': 'data_protection',
                'severity': 'medium',
                'description': 'S3 bucket versioning should be enabled',
                'remediation': 'Enable versioning on the S3 bucket',
                'remediation_command': 'aws s3api put-bucket-versioning --bucket {resource-id} --versioning-configuration Status=Enabled',
                'check': {
                    'type': 'property_value',
                    'property': 'Versioning.Status',
                    'operator': 'not_equals',
                    'values': ['Enabled']
                }
            })
            
        # EC2 specific rules
        elif service_name == 'ec2':
            rules.append({
                'id': 'ec2_ebs_encryption',
                'service_name': 'ec2',
                'property_name': 'EbsOptimized',
                'pattern_name': 'performance',
                'severity': 'low',
                'description': 'EC2 instances should use EBS optimization when possible',
                'remediation': 'Enable EBS optimization for the EC2 instance',
                'remediation_command': 'aws ec2 modify-instance-attribute --instance-id {resource-id} --ebs-optimized',
                'check': {
                    'type': 'property_value',
                    'property': 'EbsOptimized',
                    'operator': 'equals',
                    'values': [False, 'false', 'False', None]
                }
            })
            
        # Add more service-specific rules as needed
            
        return rules
        
    def evaluate_rule(self, rule: Dict, resource: Dict) -> Optional[Dict]:
        """
        Evaluate a rule against a resource
        
        Args:
            rule: Rule definition
            resource: Resource to evaluate
            
        Returns:
            Finding dictionary if rule is violated, None otherwise
        """
        check = rule['check']
        check_type = check['type']
        property_name = check['property']
        
        # Get property value using dot notation
        property_parts = property_name.split('.')
        property_value = resource
        for part in property_parts:
            if isinstance(property_value, dict) and part in property_value:
                property_value = property_value[part]
            else:
                property_value = None
                break
                
        # Property exists check
        if check_type == 'property_exists':
            if property_value is None:
                return {
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'resource_id': self._get_resource_id(resource),
                    'remediation': rule['remediation'],
                    'remediation_command': rule['remediation_command'].format(**{
                        'resource-id': self._get_resource_id(resource)
                    })
                }
                
        # Property value check
        elif check_type == 'property_value':
            operator = check['operator']
            check_values = check['values']
            
            if operator == 'equals' and property_value in check_values:
                return {
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'resource_id': self._get_resource_id(resource),
                    'remediation': rule['remediation'],
                    'remediation_command': rule['remediation_command'].format(**{
                        'resource-id': self._get_resource_id(resource)
                    })
                }
                
            elif operator == 'not_equals' and property_value not in check_values:
                return {
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'resource_id': self._get_resource_id(resource),
                    'remediation': rule['remediation'],
                    'remediation_command': rule['remediation_command'].format(**{
                        'resource-id': self._get_resource_id(resource)
                    })
                }
                
            elif operator == 'contains' and property_value is not None:
                # Check if property value contains any check values
                property_str = str(property_value).lower()
                for check_value in check_values:
                    if str(check_value).lower() in property_str:
                        return {
                            'rule_id': rule['id'],
                            'severity': rule['severity'],
                            'description': rule['description'],
                            'resource_id': self._get_resource_id(resource),
                            'remediation': rule['remediation'],
                            'remediation_command': rule['remediation_command'].format(**{
                                'resource-id': self._get_resource_id(resource)
                            })
                        }
                        
        return None
        
    def _get_resource_id(self, resource: Dict) -> str:
        """
        Get a resource identifier
        
        Args:
            resource: Resource dictionary
            
        Returns:
            Resource identifier
        """
        # Common resource identifier properties
        id_properties = [
            'Id', 'id', 'ID',
            'Name', 'name',
            'Arn', 'arn',
            'ResourceId', 'resourceId',
            'BucketName', 'bucketName',
            'InstanceId', 'instanceId',
            'FunctionName', 'functionName',
            'TableName', 'tableName',
            'ClusterName', 'clusterName'
        ]
        
        for prop in id_properties:
            if prop in resource:
                return resource[prop]
                
        # Fall back to first property
        if resource:
            first_key = next(iter(resource))
            return f"{first_key}:{resource[first_key]}"
            
        return "unknown"
