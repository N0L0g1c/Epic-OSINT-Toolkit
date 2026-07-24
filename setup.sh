#!/bin/bash
# Epic OSINT Toolkit Setup Script for Linux/Mac
set -euo pipefail

echo "Epic OSINT Toolkit - Setup"
echo "========================="
echo ""

cd "$(dirname "$0")"

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"

create_venv() {
    if [ -d "venv" ]; then
        echo "Virtual environment already exists, skipping..."
        return
    fi

    if command -v uv &> /dev/null; then
        echo "Creating virtual environment with uv..."
        uv venv venv
    elif python3 -m venv -h &> /dev/null; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    else
        echo "ERROR: Cannot create a virtual environment."
        echo "Install one of: python3-venv (apt) or uv (https://docs.astral.sh/uv/)"
        exit 1
    fi
    echo "Virtual environment created!"
}

install_deps() {
    # shellcheck disable=SC1091
    source venv/bin/activate
    if command -v uv &> /dev/null; then
        echo "Installing dependencies with uv..."
        uv pip install -r requirements.txt
    else
        echo "Upgrading pip..."
        python -m pip install --upgrade pip
        echo "Installing dependencies..."
        python -m pip install -r requirements.txt
    fi
}

echo ""
create_venv
echo ""
install_deps

mkdir -p reports
chmod +x osint_toolkit.py setup.sh

echo ""
echo "========================="
echo "Setup completed successfully!"
echo ""
echo "To use the toolkit:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run the tool: python osint_toolkit.py -t example.com --dns --ssl"
echo ""
