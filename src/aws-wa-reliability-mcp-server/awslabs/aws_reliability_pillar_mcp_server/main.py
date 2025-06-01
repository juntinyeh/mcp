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

"""Entry point for the AWS Well-Architected Reliability Pillar MCP Server."""

import sys
import os
import argparse
import asyncio
from loguru import logger

# Import the server module
from awslabs.aws_reliability_pillar_mcp_server.server import main as server_main

def main():
    """Main entry point for the AWS Well-Architected Reliability Pillar MCP Server."""
    # Set up logging
    log_level = os.getenv("FASTMCP_LOG_LEVEL", "INFO")
    logger.remove()
    logger.add(sys.stderr, level=log_level)
    
    logger.info("Starting AWS Well-Architected Reliability Pillar MCP Server")
    
    # Run the server
    server_main()

if __name__ == "__main__":
    main()
