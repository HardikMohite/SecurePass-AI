#!/bin/bash

# SecurePass Chart Directory Setup Script
# This script creates the necessary directory structure for chart storage

echo "Setting up SecurePass chart directories..."

# Create the reports output directory in static folder
mkdir -p frontend/static/reports/output

# Set proper permissions
chmod 755 frontend/static/reports
chmod 755 frontend/static/reports/output

echo "✓ Created frontend/static/reports/output/"

# Check if old reports/output exists and has files
if [ -d "reports/output" ] && [ "$(ls -A reports/output)" ]; then
    echo "Found existing charts in reports/output/"
    echo "Copying charts to new location..."
    cp reports/output/*.png frontend/static/reports/output/ 2>/dev/null || true
    echo "✓ Charts copied to frontend/static/reports/output/"
fi

echo ""
echo "Setup complete! Charts will now be accessible via the web interface."
echo "Path: /static/reports/output/"