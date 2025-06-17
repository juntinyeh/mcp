#!/bin/bash

# AWS Well-Architected Security Pillar Review MCP Server - Deployment Script
# This script sets up a local development environment for the MCP server

set -e  # Exit immediately if a command exits with a non-zero status

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Python version
print_message "Checking Python version..."
if command -v python3 >/dev/null 2>&1; then
    python_version=$(python3 --version | cut -d " " -f 2)
    python_major=$(echo $python_version | cut -d. -f1)
    python_minor=$(echo $python_version | cut -d. -f2)
    
    if [ "$python_major" -lt 3 ] || ([ "$python_major" -eq 3 ] && [ "$python_minor" -lt 12 ]); then
        print_error "Python 3.12 or higher is required. Found Python $python_version"
        exit 1
    else
        print_message "Found Python $python_version"
    fi
else
    print_error "Python 3 not found. Please install Python 3.12 or higher."
    exit 1
fi

# Define virtual environment name
VENV_NAME="venv"

# Check if virtual environment already exists
if [ -d "$VENV_NAME" ]; then
    print_warning "Virtual environment '$VENV_NAME' already exists."
    read -p "Do you want to remove it and create a new one? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_message "Removing existing virtual environment..."
        rm -rf "$VENV_NAME"
    else
        print_message "Using existing virtual environment."
    fi
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_NAME" ]; then
    print_message "Creating Python virtual environment..."
    python3 -m venv "$VENV_NAME"
fi

# Activate virtual environment
print_message "Activating virtual environment..."
source "$VENV_NAME/bin/activate"

# Upgrade pip
print_message "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
print_message "Installing dependencies from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    print_error "requirements.txt not found!"
    exit 1
fi

# Install the package in development mode
print_message "Installing the package in development mode..."
pip install -e .

# Check if installation was successful
if [ $? -eq 0 ]; then
    print_message "Installation completed successfully!"
    
    # Create local configuration for Amazon Q
    print_message "Setting up local configuration for Amazon Q..."
    
    # Create .amazonq directory if it doesn't exist
    mkdir -p ~/.amazonq
    
    # Copy the configuration file
    print_message "Copying configuration file to ~/.amazonq/mcp.json..."
    cp aws_amazonq_mcp-config.json ~/.amazonq/mcp.json
    
    # Update the workspace path in the configuration file
    print_message "Updating workspace path in configuration..."
    sed -i '' 's|<WOKRSPACE_PATH>|.|g' ~/.amazonq/mcp.json
    
    echo
    echo -e "${GREEN}=== AWS Well-Architected Security Pillar Review MCP Server ===${NC}"
    echo "The development environment has been set up successfully."
    echo
    echo "To activate the virtual environment in the future, run:"
    echo "  source $VENV_NAME/bin/activate"
    echo
    echo "To run the server:"
    echo "  python awslabs/aws_wa_sec_review_mcp_server/server.py"
    echo
    echo "To run with SSE transport:"
    echo "  python awslabs/aws_wa_sec_review_mcp_server/server.py --sse"
    echo
    echo "To run on a specific port:"
    echo "  python awslabs/aws_wa_sec_review_mcp_server/server.py --port 8889"
    echo
    echo "Amazon Q configuration has been set up at ~/.amazonq/mcp.json"
    echo
else
    print_error "Installation failed!"
    exit 1
fi
