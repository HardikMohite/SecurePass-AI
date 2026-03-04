@echo off
REM SecurePass Chart Directory Setup Script for Windows
REM This script creates the necessary directory structure for chart storage

echo Setting up SecurePass chart directories...

REM Create the reports output directory in static folder
if not exist "frontend\static\reports" mkdir "frontend\static\reports"
if not exist "frontend\static\reports\output" mkdir "frontend\static\reports\output"

echo [OK] Created frontend\static\reports\output\

REM Check if old reports\output exists and has files
if exist "reports\output\*.png" (
    echo Found existing charts in reports\output\
    echo Copying charts to new location...
    copy "reports\output\*.png" "frontend\static\reports\output\" >nul 2>&1
    echo [OK] Charts copied to frontend\static\reports\output\
)

echo.
echo Setup complete! Charts will now be accessible via the web interface.
echo Path: /static/reports/output/
echo.
echo You can now run: python app.py
pause