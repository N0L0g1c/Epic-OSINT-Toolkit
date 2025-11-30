#!/bin/bash
# Epic OSINT Toolkit Setup Script for Linux/Mac
# Run this script to set up the toolkit

echo "Epic OSINT Toolkit - Setup"
echo "========================="
echo ""

# Check Python
echo "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "Found: $PYTHON_VERSION"
else
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Check pip
echo "Checking pip..."
if command -v pip3 &> /dev/null; then
    PIP_VERSION=$(pip3 --version)
    echo "Found: $PIP_VERSION"
else
    echo "ERROR: pip3 is not installed"
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists, skipping..."
else
    python3 -m venv venv
    echo "Virtual environment created!"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

# Create reports directory
echo ""
echo "Creating reports directory..."
if [ ! -d "reports" ]; then
    mkdir -p reports
    echo "Reports directory created!"
else
    echo "Reports directory already exists"
fi

# Make script executable
chmod +x osint_toolkit.py

echo ""
echo "========================="
echo "Setup completed successfully!"
echo ""
echo "To use the toolkit:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run the tool: python osint_toolkit.py -t example.com --full"
echo ""

