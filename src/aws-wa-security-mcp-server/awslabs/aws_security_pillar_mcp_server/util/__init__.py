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

"""Utility functions for AWS Security Pillar MCP Server."""

from awslabs.aws_security_pillar_mcp_server.util.security_services import (
    check_access_analyzer,
    check_security_hub,
    check_guard_duty,
    check_inspector,
    get_guardduty_findings,
    get_securityhub_findings,
    get_inspector_findings,
    get_access_analyzer_findings,
)

from awslabs.aws_security_pillar_mcp_server.util.resource_utils import (
    list_resources_by_service,
    list_all_resources,
    resource_inventory_summary,
    get_tagged_resources,
    get_resource_compliance_status,
    list_aws_regions,
)

# Export all imported functions
__all__ = [
    # Security service functions
    'check_access_analyzer',
    'check_security_hub',
    'check_guard_duty',
    'check_inspector',
    'get_guardduty_findings',
    'get_securityhub_findings',
    'get_inspector_findings',
    'get_access_analyzer_findings',
    
    # Resource utility functions
    'list_resources_by_service',
    'list_all_resources',
    'resource_inventory_summary',
    'get_tagged_resources',
    'get_resource_compliance_status',
    'list_aws_regions',
]
