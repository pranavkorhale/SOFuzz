#!/bin/bash
# SOFuzz - Clean Script

echo "=================================="
echo "SOFuzz - Cleaning Output Files"
echo "=================================="

# Remove output directories
rm -rf output/
rm -rf crashes/
rm -rf harnesses/
rm -rf reports/
rm -rf __pycache__/
rm -rf sofuzz/__pycache__/
rm -rf sofuzz/*/__pycache__/
rm -rf .pytest_cache/
rm -rf *.egg-info/
rm -rf build/
rm -rf dist/

# Remove temporary files
find . -name "*.pyc" -delete
find . -name "*.pyo" -delete
find . -name ".DS_Store" -delete

echo "Cleaned!"