#!/bin/bash
# SOFuzz - Run Tests Script

echo "=================================="
echo "SOFuzz - Running Tests"
echo "=================================="

# Run all tests
python3 -m pytest tests/ -v

# Or run with unittest
# python3 -m unittest discover -s tests -v

echo ""
echo "=================================="
echo "Tests Complete!"
echo "=================================="