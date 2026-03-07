#!/bin/bash
# SOFuzz - Install Dependencies Script

echo "=================================="
echo "SOFuzz - Installing Dependencies"
echo "=================================="

# Check Python version
python3 --version || { echo "Python 3 is required"; exit 1; }

# Install Python dependencies
echo ""
echo "Installing Python packages..."
pip3 install -r requirements.txt

# Check for GCC
echo ""
echo "Checking for GCC..."
if command -v gcc &> /dev/null; then
    echo "GCC found: $(gcc --version | head -n1)"
else
    echo "WARNING: GCC not found. Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install build-essential"
    echo "  macOS: xcode-select --install"
fi

# Check for optional tools
echo ""
echo "Checking optional tools..."

if command -v readelf &> /dev/null; then
    echo "readelf: found"
else
    echo "readelf: not found (optional)"
fi

if command -v nm &> /dev/null; then
    echo "nm: found"
else
    echo "nm: not found (optional)"
fi

if command -v objdump &> /dev/null; then
    echo "objdump: found"
else
    echo "objdump: not found (optional)"
fi

# Install SOFuzz
echo ""
echo "Installing SOFuzz..."
pip3 install -e .

echo ""
echo "=================================="
echo "Installation Complete!"
echo "=================================="
echo ""
echo "Run 'sofuzz --help' to get started."