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

"""Security patterns catalog for AWS security best practices."""

import requests
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Any, Optional, Set, Literal
from loguru import logger
from pydantic import BaseModel, Field

class SecurityPattern(BaseModel):
    """Security pattern derived from AWS Well-Architected Framework."""
    
    id: str = Field(..., description="Unique identifier for the pattern")
    description: str = Field(..., description="Human-readable description")
    keywords: List[str] = Field(default_factory=list, description="Keywords for pattern matching")
    regex_patterns: List[str] = Field(default_factory=list, description="Regex patterns for advanced matching")
    severity: Literal["critical", "high", "medium", "low"] = Field("medium", description="Security severity level")
    remediation_template: str = Field(..., description="Template for remediation instructions")
    wa_domain: str = Field(..., description="Well-Architected Framework domain")
    relevant_content: Optional[List[Dict[str, str]]] = Field(None, description="Related content from documentation")


class BestPractice(BaseModel):
    """Best practice from AWS Well-Architected Framework."""
    
    id: str = Field(..., description="Best practice identifier (e.g., SEC01-BP01)")
    title: str = Field(..., description="Title of the best practice")
    content: str = Field(..., description="Content describing the best practice")
    domain: str = Field(..., description="Well-Architected Framework domain")
    keywords: List[str] = Field(default_factory=list, description="Keywords extracted from content")


class SecurityPatternCatalog:
    """Catalog of security patterns derived from AWS Well-Architected Framework.
    
    This catalog provides security patterns that can be used to evaluate AWS resources
    against Well-Architected Framework best practices. The patterns are automatically
    enhanced with content from AWS documentation when available.
    """
    
    def __init__(self):
        """Initialize the security pattern catalog"""
        # Base patterns - will be enhanced with documentation
        self.base_patterns = {
            'public_access': {
                'id': 'public_access',
                'description': 'Public access controls',
                'keywords': ['public', 'everyone', 'allusers', 'anonymous'],
                'regex_patterns': ['public.*', '.*public', 'global.*'],
                'severity': 'high',
                'remediation_template': 'Configure {property} to restrict public access',
                'wa_domain': 'identity_and_access_management'
            },
            'encryption': {
                'id': 'encryption',
                'description': 'Data encryption',
                'keywords': ['encrypt', 'kms', 'ssl', 'tls'],
                'regex_patterns': ['encrypt.*', '.*encrypt', 'ssl.*', 'tls.*'],
                'severity': 'high',
                'remediation_template': 'Enable encryption for {property}',
                'wa_domain': 'data_protection'
            },
            'logging': {
                'id': 'logging',
                'description': 'Logging and monitoring',
                'keywords': ['log', 'audit', 'trail'],
                'regex_patterns': ['log.*', '.*log', 'audit.*', '.*trail'],
                'severity': 'medium',
                'remediation_template': 'Enable logging for {property}',
                'wa_domain': 'detection'
            },
            'authentication': {
                'id': 'authentication',
                'description': 'Authentication and authorization',
                'keywords': ['auth', 'iam', 'role', 'permission', 'policy', 'cred'],
                'regex_patterns': ['auth.*', 'iam.*', '.*role', '.*policy', '.*permission'],
                'severity': 'high',
                'remediation_template': 'Configure proper authentication for {property}',
                'wa_domain': 'identity_and_access_management'
            },
            'network_security': {
                'id': 'network_security',
                'description': 'Network security',
                'keywords': ['vpc', 'subnet', 'security group', 'nacl', 'firewall'],
                'regex_patterns': ['vpc.*', '.*vpc', 'private.*', 'security.*group', 'firewall.*'],
                'severity': 'high',
                'remediation_template': 'Review network security settings for {property}',
                'wa_domain': 'infrastructure_protection'
            }
        }
        
        # Domain-to-URL mapping in Well-Architected Framework
        self.wa_domains = {
            'identity_and_access_management': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/identity-and-access-management.html',
            'detection': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/detection.html',
            'infrastructure_protection': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/infrastructure-protection.html',
            'data_protection': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/data-protection.html',
            'incident_response': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html',
            'application_security': 'https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/application-security.html'
        }
        
        # Initialize patterns with base patterns
        self.patterns = dict(self.base_patterns)
        self.best_practices = {}
        
    async def initialize(self):
        """Initialize the security pattern catalog.
        
        Enhances the base patterns with documentation from the AWS Well-Architected
        Framework when available. Falls back to embedded patterns if documentation
        cannot be accessed.
        """
        # Try to enhance patterns with documentation
        try:
            await self._load_patterns_from_wa_documentation()
            logger.info("Security patterns enhanced with Well-Architected documentation")
        except Exception as e:
            logger.warning(f"Could not enhance patterns with Well-Architected documentation: {e}")
            # Fall back to embedded patterns
            self.patterns = dict(self.base_patterns)
        
    async def _load_patterns_from_wa_documentation(self):
        """Load security patterns from Well-Architected documentation.
        
        Fetches the AWS Well-Architected Framework Security Pillar documentation
        and extracts best practices to enhance the security patterns.
        """
        # Process each security domain
        for domain, url in self.wa_domains.items():
            try:
                # Fetch documentation
                doc_content = await self._fetch_documentation(url)
                
                if doc_content:
                    # Extract best practices
                    best_practices = self._extract_best_practices(doc_content, domain)
                    self.best_practices[domain] = best_practices
                    
                    # Enhance patterns with best practices
                    self._enhance_patterns_with_best_practices(domain, best_practices)
                    
            except Exception as e:
                logger.warning(f"Error loading documentation for {domain}: {e}")
                
    async def _fetch_documentation(self, url: str) -> Optional[str]:
        """Fetch documentation from a URL.
        
        Makes an HTTP request to retrieve AWS documentation content.
        
        Args:
            url: Documentation URL to fetch
            
        Returns:
            Documentation content as string if successful, None otherwise
            
        Note:
            This method uses synchronous requests in an async context as a simplification.
            In a production environment, consider using aiohttp or httpx for async requests.
        """
        try:
            # Fetch documentation
            response = requests.get(url)
            response.raise_for_status()
            
            return response.text
        except Exception as e:
            logger.warning(f"Error fetching documentation from {url}: {e}")
            return None
            
    def _extract_best_practices(self, content: str, domain: str) -> List[Dict]:
        """Extract best practices from documentation.
        
        Parses HTML content to identify and extract Well-Architected best practices.
        
        Args:
            content: HTML documentation content
            domain: Security domain identifier
            
        Returns:
            List of best practice dictionaries containing id, title, content, domain, and keywords
        """
        best_practices = []
        
        try:
            # Parse HTML
            soup = BeautifulSoup(content, 'html.parser')
            
            # Look for best practice sections
            # Well-Architected best practices are typically labeled as "SEC01-BP01", etc.
            bp_pattern = re.compile(r'SEC\d+-BP\d+')
            
            # Find all headings
            for heading in soup.find_all(['h2', 'h3', 'h4']):
                text = heading.get_text().strip()
                
                # Check if it's a best practice
                if bp_pattern.search(text) or 'best practice' in text.lower():
                    bp_id = bp_pattern.search(text).group(0) if bp_pattern.search(text) else None
                    
                    # Extract description
                    description = text.replace(bp_id, '').strip() if bp_id else text
                    
                    # Extract content
                    content = []
                    current = heading.next_sibling
                    
                    while current and current.name not in ['h2', 'h3', 'h4']:
                        if current.name and current.get_text().strip():
                            content.append(current.get_text().strip())
                        current = current.next_sibling
                    
                    # Create best practice
                    best_practice = {
                        'id': bp_id or f"{domain}_{len(best_practices)}",
                        'title': description,
                        'content': ' '.join(content),
                        'domain': domain,
                        'keywords': self._extract_keywords_from_content(' '.join(content))
                    }
                    
                    best_practices.append(best_practice)
                    
        except Exception as e:
            logger.warning(f"Error extracting best practices from {domain}: {e}")
            
        return best_practices
        
    def _extract_keywords_from_content(self, content: str) -> List[str]:
        """Extract security-related keywords from content.
        
        Analyzes text content to identify security-related terms and concepts.
        
        Args:
            content: Text content to analyze
            
        Returns:
            List of security-related keywords found in the content
        """
        # Common security keywords
        security_terms = [
            'encrypt', 'authentication', 'authorization', 'audit',
            'log', 'monitor', 'access', 'permission', 'role', 'policy',
            'secret', 'credential', 'key', 'certificate', 'tls', 'ssl',
            'firewall', 'network', 'public', 'private', 'secure', 'protect',
            'detect', 'incident', 'response', 'vulnerability', 'kms', 'cmk',
            'mfa', 'identity', 'tls', 'https', 'vpn', 'nacl', 'bastion'
        ]
        
        keywords = []
        content_lower = content.lower()
        
        # Check for each term
        for term in security_terms:
            if term in content_lower:
                keywords.append(term)
                
        return keywords
        
    def _enhance_patterns_with_best_practices(self, domain: str, best_practices: List[Dict]):
        """Enhance security patterns with best practices.
        
        Integrates relevant best practices into security patterns to provide
        more comprehensive guidance and context.
        
        Args:
            domain: Security domain identifier
            best_practices: List of best practice dictionaries
        """
        # Find patterns in this domain
        domain_patterns = {
            pattern_id: pattern for pattern_id, pattern in self.patterns.items()
            if pattern.get('wa_domain') == domain
        }
        
        # Enhance each pattern
        for pattern_id, pattern in domain_patterns.items():
            for best_practice in best_practices:
                # Check if best practice is relevant to pattern
                if self._is_best_practice_relevant_to_pattern(best_practice, pattern):
                    # Add keywords from best practice
                    pattern['keywords'].extend(best_practice.get('keywords', []))
                    
                    # Add relevant content
                    if 'relevant_content' not in pattern:
                        pattern['relevant_content'] = []
                        
                    pattern['relevant_content'].append({
                        'id': best_practice['id'],
                        'title': best_practice['title'],
                        'summary': best_practice['content'][:200] + '...' if len(best_practice['content']) > 200 else best_practice['content']
                    })
                    
            # Remove duplicates from keywords
            pattern['keywords'] = list(set(pattern['keywords']))
            
    def _is_best_practice_relevant_to_pattern(self, best_practice: Dict, pattern: Dict) -> bool:
        """Check if a best practice is relevant to a security pattern.
        
        Determines relevance by analyzing keyword overlap and content similarity.
        
        Args:
            best_practice: Best practice dictionary
            pattern: Security pattern dictionary
            
        Returns:
            True if the best practice is relevant to the pattern, False otherwise
        """
        # Check if any pattern keywords are in the best practice
        for keyword in pattern['keywords']:
            if keyword.lower() in best_practice['title'].lower() or keyword.lower() in best_practice['content'].lower():
                return True
                
        # Check if any best practice keywords match pattern keywords
        for bp_keyword in best_practice.get('keywords', []):
            if bp_keyword in pattern['keywords']:
                return True
                
        return False
        
    def get_pattern(self, pattern_id: str) -> Optional[Dict]:
        """Get a security pattern by its identifier.
        
        Args:
            pattern_id: Pattern identifier (e.g., 'public_access', 'encryption')
            
        Returns:
            Security pattern dictionary if found, None otherwise
        """
        return self.patterns.get(pattern_id)
        
    def get_patterns_for_domain(self, domain: str) -> Dict:
        """Get all security patterns for a specific domain.
        
        Args:
            domain: Security domain identifier (e.g., 'identity_and_access_management')
            
        Returns:
            Dictionary of security patterns for the domain, keyed by pattern ID
        """
        return {
            pattern_id: pattern for pattern_id, pattern in self.patterns.items()
            if pattern.get('wa_domain') == domain
        }
        
    def get_best_practices_for_domain(self, domain: str) -> List[Dict]:
        """Get all best practices for a specific domain.
        
        Args:
            domain: Security domain identifier (e.g., 'identity_and_access_management')
            
        Returns:
            List of best practice dictionaries for the domain
        """
        return self.best_practices.get(domain, [])
