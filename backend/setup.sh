#!/bin/bash

# Always run relative to this script's own location (backend/), regardless
# of which directory it was invoked from. This also guarantees the venv
# created below lands at backend/.venv, not at the project root.
cd "$(dirname "$0")"

echo "🔒 SecurePass AI - Setup Script"
echo "================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"
echo ""

# Create virtual environment (backend/.venv) if it doesn't exist yet
if [ ! -d ".venv" ]; then
    echo "🐍 Creating virtual environment (backend/.venv)..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
    echo "✓ Virtual environment created at backend/.venv"
else
    echo "✓ Virtual environment already exists at backend/.venv, skipping creation..."
fi
echo ""

# Activate it for the rest of this script
echo "⚙️  Activating virtual environment..."
source .venv/bin/activate
echo "✓ Activated: $(which python3)"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi
echo "✓ Dependencies installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > .env << EOF
# SecurePass AI - Environment Variables
SECRET_KEY=$SECRET_KEY
FLASK_ENV=development
FLASK_DEBUG=True
DATABASE_URL=sqlite:///securepass.db
SESSION_COOKIE_SECURE=False
REMEMBER_COOKIE_SECURE=False
EOF
    echo "✓ .env file created with secure secret key"
else
    echo "⚠️  .env file already exists, skipping..."
fi
echo ""

# Initialize database
echo "🗄️  Initializing database..."
python3 init_db.py
if [ $? -ne 0 ]; then
    echo "❌ Failed to initialize database"
    exit 1
fi
echo ""

echo "✅ Setup complete!"
echo ""
echo "To start the application:"
echo "  source .venv/bin/activate   # if not already active in this shell"
echo "  python3 app.py"
echo ""
echo "Then visit: http://localhost:5000"
echo ""
echo "⚠️  Default admin credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo "  (Please change this password immediately!)"