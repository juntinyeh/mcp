"""
Dynamic rule catalog for AWS security rules
"""

import logging
import asyncio
import os
import importlib
import sys
from typing import Dict, List, Any, Optional, Set, Callable

logger = logging.getLogger(__name__)

class RuleCatalog:
    """
    Dynamic rule catalog that manages security rules
    """
    
    def __init__(self):
        """Initialize the rule catalog"""
        # Rules by service
        self.rules = {}
        # Rule generators
        self.rule_generators = []
        # External sources
        self.external_sources = {}
        
    async def initialize(self):
        """Initialize the rule catalog"""
        # Look for external rule sources
        await self._load_external_sources()
        logger.info("Rule catalog initialized")
        
    def register_rule(self, rule: Dict):
        """
        Register a rule with the catalog
        
        Args:
            rule: Rule definition
        """
        service_name = rule['service_name']
        
        if service_name not in self.rules:
            self.rules[service_name] = []
            
        # Check if rule already exists
        for existing_rule in self.rules[service_name]:
            if existing_rule['id'] == rule['id']:
                # Replace existing rule
                self.rules[service_name].remove(existing_rule)
                break
                
        self.rules[service_name].append(rule)
        logger.debug(f"Registered rule: {rule['id']}")
        
    def register_rule_generator(self, generator: Any):
        """
        Register a rule generator
        
        Args:
            generator: Rule generator instance
        """
        self.rule_generators.append(generator)
        logger.debug(f"Registered rule generator: {generator.__class__.__name__}")
        
    async def _load_external_sources(self):
        """Load rules from external sources"""
        # Check for environment variables defining external sources
        github_repo = os.environ.get('SECURITY_RULES_REPO')
        if github_repo:
            await self._load_rules_from_github(github_repo)
            
        # Check for local rule directories
        local_rules_dir = os.environ.get('SECURITY_RULES_DIR')
        if local_rules_dir and os.path.isdir(local_rules_dir):
            await self._load_rules_from_directory(local_rules_dir)
            
    async def _load_rules_from_github(self, repo_url: str):
        """Load rules from a GitHub repository"""
        # This would require git to be installed
        # For now, just log a message
        logger.info(f"Loading external rules from GitHub is not yet implemented: {repo_url}")
            
    async def _load_rules_from_directory(self, directory: str):
        """Load rules from a directory"""
        logger.info(f"Loading external rules from directory: {directory}")
        
        try:
            # Look for Python files in the directory
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.py') and not file.startswith('__'):
                        file_path = os.path.join(root, file)
                        
                        # Load the module
                        module_name = os.path.basename(file)[:-3]  # Remove .py
                        spec = importlib.util.spec_from_file_location(module_name, file_path)
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = module
                        spec.loader.exec_module(module)
                        
                        # Look for rule classes and functions
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            
                            # Check if it's a rule class or function
                            if hasattr(attr, 'is_security_rule') and attr.is_security_rule:
                                self._register_external_rule(attr, module_name)
                                
        except Exception as e:
            logger.error(f"Error loading rules from directory: {e}")
    
    def _register_external_rule(self, rule_obj: Any, source: str):
        """Register an external rule"""
        try:
            # For classes, instantiate
            if isinstance(rule_obj, type):
                rule_instance = rule_obj()
                rule_meta = rule_instance()
            # For functions, call to get metadata
            else:
                rule_meta = rule_obj()
                
            service = rule_meta.get('service_name')
            
            if service:
                # Create rule
                rule = {
                    'id': rule_meta.get('id', f"{service}_{source}"),
                    'service_name': service,
                    'property_name': rule_meta.get('property_name', ''),
                    'pattern_name': rule_meta.get('pattern_name', 'custom'),
                    'severity': rule_meta.get('severity', 'medium'),
                    'description': rule_meta.get('description', 'Custom rule'),
                    'remediation': rule_meta.get('remediation', 'See documentation'),
                    'remediation_command': rule_meta.get('remediation_command', ''),
                    'source': source,
                    'check': rule_meta.get('check', {})
                }
                
                self.register_rule(rule)
                logger.debug(f"Registered external rule: {rule['id']} from {source}")
        except Exception as e:
            logger.error(f"Error registering external rule: {e}")
    
    async def get_rules_for_service(self, service_name: str) -> List[Dict]:
        """
        Get all rules for a specific service
        
        Args:
            service_name: AWS service name
            
        Returns:
            List of rules for the service
        """
        # Get pre-registered rules
        rules = self.rules.get(service_name, []).copy()
        
        # Generate rules from generators
        for generator in self.rule_generators:
            try:
                dynamic_rules = await generator.generate_rules_for_service(service_name)
                for rule in dynamic_rules:
                    # Add to catalog and return list
                    self.register_rule(rule)
                    rules.append(rule)
            except Exception as e:
                logger.error(f"Error generating rules for {service_name}: {e}")
                
        return rules
    
    async def evaluate_resources(self, service_name: str, resources: Dict) -> Dict:
        """
        Evaluate resources against rules
        
        Args:
            service_name: AWS service name
            resources: Resources to evaluate
            
        Returns:
            Dictionary of findings by resource type
        """
        findings = {}
        
        # Get rules for this service
        rules = await self.get_rules_for_service(service_name)
        
        # Process each resource type
        for resource_type, resource_list in resources.items():
            if not isinstance(resource_list, list):
                continue
                
            resource_findings = []
            
            # Evaluate each resource
            for resource in resource_list:
                if not isinstance(resource, dict):
                    continue
                    
                # Apply each rule
                for rule in rules:
                    try:
                        # Import dynamically to avoid circular imports
                        from awslabs.aws_security_pillar_mcp_server.rules.rule_generator import DynamicRuleGenerator
                        
                        # Create rule evaluator if we don't have one
                        rule_evaluator = DynamicRuleGenerator()
                        
                        # Evaluate the rule
                        finding = rule_evaluator.evaluate_rule(rule, resource)
                        
                        if finding:
                            resource_findings.append(finding)
                    except Exception as e:
                        logger.error(f"Error evaluating rule {rule['id']}: {e}")
                        
            if resource_findings:
                findings[resource_type] = resource_findings
                
        return findings
